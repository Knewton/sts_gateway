#!perl
#
#  Last edited by:  $Author: mselby $
#              on:  $Date: 2012-07-10 18:41:07 -0600 (Tue, 10 Jul 2012) $
#        Revision:  $Revision: 63087 $
#

package Knewton::Systems::Amazon::STS;

use strict;
use warnings;

use Data::Dumper;
use LWP::UserAgent;
use HTTP::Request::Common;
use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::SHA qw(hmac_sha256 sha1_hex);
use POSIX qw(strftime);
use URI;
use URI::Escape;
use XML::Simple;
use JSON;

our $errstr;

my $cf = {
          'accounts'    => [ qw(<ACCOUNT NAME 1> <ACCOUNT NAME 2>) ],
          'accessTypes' => [ qw(readonly readwrite) ],          
          'endpoints'   => {
                            'sts'     => 'https://sts.amazonaws.com/', # require trailing slash
                            'signin'  => 'https://signin.aws.amazon.com/federation', # no trailing slash
                            'issuer'  => 'https://login.yourcompany.net/',
                            'console' => 'https://console.aws.amazon.com/',
                           },
          'duration'    => {
                            'min'     => 3600,   # 1 hour
                            'max'     => 129600, # 36 hours
                            'default' => 28800,  # 8 hours
                           },
         };

sub new {
  my $class = shift;
  my %args = @_;
  
  my $credentials;
  eval {
    $credentials = require "/usr/local/lib/perl5/Knewton/Systems/Amazon/STSCreds.pl";
  };
  if ($@) {
    $errstr = "Could not obtain needed credentials, $@";
    return undef;
  }

  my $innetgr = '/usr/local/bin/innetgr';
  if (! -x $innetgr) {
    $errstr = "$innetgr does not exist or is not executable";
    return undef;
  }
  
  my $debug = defined $args{'debug'} ? $args{'debug'} : 0;
  
  my $self = {
              'cf'              => $cf,
              'credentials'     => $credentials,
              'innetgr'         => $innetgr,
              'debug'           => $debug,
             };
  
  return bless $self, ref $class || $class;
}

sub getAPICredentials {
  my $self = shift;
  my %args = @_;

  my $cf = $self->{'cf'};
  
  foreach my $arg (qw(user account access)) {
    if (!$args{$arg}) {
      $self->error("argument $arg is required but was not supplied");
      return 0;
    }
  }

  my $user = $args{'user'};
  my $account = $args{'account'};
  my $access = $args{'access'};

  if (!grep /^$account$/, @{$cf->{'accounts'}}) {
    $self->error("$account is not a valid account");
    return 0;
  }

  if (!grep /^$access$/, @{$cf->{'accessTypes'}}) {
    $self->error("$access is not a valid access type");
    return 0;
  }

  my $defaultDuration = $cf->{'duration'}->{'default'};
  my $minDuration = $cf->{'duration'}->{'min'};
  my $maxDuration = $cf->{'duration'}->{'max'};

  my $duration = defined $args{'duration'} ? $args{'duration'} : $defaultDuration;
  if ($duration < $minDuration || $duration > $maxDuration ) {
    $self->error("duration must be between $minDuration and $maxDuration");
    return 0;
  }

  if (!$self->_validateUser($user,$account,$access)) {
    $self->error("$user is not allowed $access access to $account");
    return 0;
  }

  my $policy = $self->_getPolicy() or return 0;

  my %query;
  $query{'Action'}          = 'GetFederationToken';
  $query{'Name'}            = "${user}-${account}";
  $query{'Policy'}          = $policy;
  $query{'DurationSeconds'} = $duration;

  my $accessKeyId = $self->{'credentials'}->{$account}->{$access}->{'access'};
  my $secretKeyId = $self->{'credentials'}->{$account}->{$access}->{'secret'};

  my $response = $self->_doAPIQuery(\%query,$accessKeyId,$secretKeyId);
 
  my $parser = XML::Simple->new();
  my $parsed = $parser->XMLin($response->decoded_content());

  if (!$response->is_success()) {
    $self->error($parsed->{'Error'}->{'Message'});
    return 0;
  } else {
    return {
            sessionToken    => $parsed->{'GetFederationTokenResult'}->{'Credentials'}->{'SessionToken'},
            accessKeyId     => $parsed->{'GetFederationTokenResult'}->{'Credentials'}->{'AccessKeyId'},
            secretAccessKey => $parsed->{'GetFederationTokenResult'}->{'Credentials'}->{'SecretAccessKey'},
            expiration      => $parsed->{'GetFederationTokenResult'}->{'Credentials'}->{'Expiration'},
           };
  }
}

sub _doAPIQuery {
  my $self = shift;
  my $query = shift;
  my $accessKeyId = shift;
  my $secretKeyId = shift;

  my $cf = $self->{'cf'};

  my $action   = 'POST';
  my $endpoint = $cf->{'endpoints'}->{'sts'};
  my $uri      = URI->new($endpoint);
  my $host     = lc($uri->host());
  my $path     = '/';

  $query->{'AWSAccessKeyId'}   = $accessKeyId;
  $query->{'Timestamp'}        = strftime("%Y-%m-%dT%H:%M:%SZ",gmtime);
  $query->{'Version'}          = '2011-06-15';
  $query->{'SignatureVersion'} = 2;
  $query->{'SignatureMethod'}  = 'HmacSHA256';

  my @params;

  foreach my $key (sort keys %{$query}) {
    my $value = $query->{$key};
    ($key,$value) = map { uri_escape($_,"^A-Za-z0-9\-_.~") } ($key,$value);
    push(@params,join('=',$key,$value))
  }
  
  my $toSign = join("\n",$action,$host,$path,join('&',@params));  
  my $signature = encode_base64(hmac_sha256($toSign,$secretKeyId),'');
  $query->{'Signature'} = $signature;

  my $request = POST $endpoint, [%{$query}];
  my $ua = LWP::UserAgent->new();

  return($ua->request($request));  
}

sub getWebCredentials {
  my $self = shift;

  my $cf = $self->{'cf'};
  
  my $apiCredentials = $self->getAPICredentials(@_);
  return 0 if (!$apiCredentials);

  my $jsonRef = {
                 sessionId    => $apiCredentials->{'accessKeyId'},
                 sessionKey   => $apiCredentials->{'secretAccessKey'},
                 sessionToken => $apiCredentials->{'sessionToken'},
                };

  my %query;
  $query{'Action'}  = 'getSigninToken';
  $query{'Session'} = uri_escape(to_json($jsonRef),"^A-Za-z0-9\-_.~");

  my $response = $self->_doWebQuery(\%query);

  my $content = $response->decoded_content();

  if (!$response->is_success()) {
    $self->error($content);
    return 0;
  } else {
    my $_content = from_json($content);
    my $signinToken = $_content->{'SigninToken'};

    my $url;
    $url .= $cf->{'endpoints'}->{'signin'} . '?';
    $url .= 'Action=login' . '&';
    $url .= 'Issuer=' . uri_escape($cf->{'endpoints'}->{'issuer'}) . '&';
    $url .= 'Destination=' . uri_escape($cf->{'endpoints'}->{'console'}) . '&';
    $url .= "SigninToken=$signinToken";
    return $url;
  }
}

sub _doWebQuery {
  my $self = shift;
  my $query = shift;

  my $cf = $self->{'cf'};

  my $endpoint = $cf->{'endpoints'}->{'signin'};

  my @params;

  foreach my $key (sort keys %{$query}) {
    push(@params,join('=',$key,$query->{$key}));
  }
  my $_query =  join('&',@params);
  my $uri = URI->new($endpoint . '?' . $_query);
  $_query = $uri->query($_query);

  my $url = $endpoint . '?' . $_query;

  my $request = GET $url;
  my $ua = LWP::UserAgent->new();
  
  return($ua->request($request));  
}


sub _validateUser {
  my $self = shift;
  my ($user,$account,$access) = @_;
  
  my @netgroups2Check = ('global-aws-readwrite-users',"${account}-aws-readwrite-users");
  if ($access eq 'readonly') {
    push(@netgroups2Check,'global-aws-readonly-users',"${account}-aws-readonly-users");
  }
  
  my $innetgr = $self->{'innetgr'};
  my $validateUser = 0;

  foreach my $netgroup (@netgroups2Check) {
    system($innetgr,"-u",$user,$netgroup);
    if (!$?) {
      $validateUser = 1;
      last;
    }
  }

  return $validateUser;
}

sub _getPolicy {
  my $self = shift;

my $policy = <<'EOF';
{
  "Statement": [
    {
      "Effect":"Allow",
      "NotAction":"iam:*",
      "Resource":"*"
    }
  ]
}
EOF
  $policy =~ s/[\s\v]//g;

  return $policy;
}

sub error {
  my $self = shift;
  my $error = shift;

  if ($error) {
    $self->{'errstr'} = $error;
  } else {
    return $self->{'errstr'};
  }
}

##############################
# Do not mess with last true #
##############################
1;

__END__
