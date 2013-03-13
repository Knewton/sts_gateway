#!/opt/perl5/bin/perl
#
#  Last edited by:  $Author: mselby $
#              on:  $Date: 2012-07-07 22:17:54 -0600 (Sat, 07 Jul 2012) $
#        Revision:  $Revision: 63044 $
#

use strict; 
use warnings;

use CGI;
use XML::Simple;
use JSON;
use POSIX qw(strftime);

use lib '/usr/local/lib/perl5';
use Knewton::Systems::Amazon::STS;

my $query = CGI->new();

my $sts = Knewton::Systems::Amazon::STS->new();

if (!$sts) {
  print $query->header(-type => 'text/plain');
  print $Knewton::Systems::Amazon::STS::errstr, "\n";
  exit 1;
}

my $user = $ENV{'REMOTE_USER'} || $ENV{'HTTP_REMOTE_USER'};

if (!$user) {
  print $query->header(-type => 'text/plain');
  print "REMOTE_USER not known, authentication issue\n";
  exit 1;
}

my $account = $query->param('account');
my $access = $query->param('access');

my $output = defined $query->param('output') ? $query->param('output') : 'xml';
my $duration = defined $query->param('duration') ? $query->param('duration') : 3600;

if (!grep /^$output$/, qw(text json xml)) {
  print $query->header(-type => 'text/plain');
  print "output must be one of (text json xml)\n";
  exit 1;
}

my $creds = $sts->getAPICredentials(
                                    'user'     => $user,
                                    'account'  => $account,
                                    'access'   => $access,
                                    'duration' => $duration,
                                   );

if (!$creds) {
  print $query->header(-type => 'text/plain');
  print $sts->error(), "\n";
  exit 1;
}

logIt($user,$account,$access,$duration);

if ($output eq 'text') {
  print $query->header(-type => 'text/plain');
  foreach my $key (keys %{$creds}) {
    my $value = $creds->{$key};
    print "${key}::${value}\n";
  }
  exit 0;
}

if ($output eq 'json') {
  print $query->header(-type => 'text/plain');
  print to_json($creds, {pretty => 1}), "\n";
  exit 0;
}

if ($output eq 'xml') {
  print $query->header(-type => 'text/plain');
  print XMLout($creds,  RootName => 'credentials', NoAttr => 1), "\n";
  exit 0;
}

sub logIt {
  my ($user,$account,$access,$duration) = @_;

  my $date = POSIX::strftime("%Y%m%d", localtime);
  my $time = POSIX::strftime("%H%M%S", localtime);
  my $logDir = "/var/systems/log/aws_sts";
  foreach my $dir ($logDir,"$logDir/$date") {
    if (! -d "$dir") {
      return undef if (!mkdir($dir));
    }
  }
  my $logFH;
  if (!open $logFH, '>', "$logDir/$date/${user}.${time}") {
    return undef;
  }
  print $logFH "$user obtained $access creds for $account with duration of $duration seconds\n";
  close($logFH);
}
