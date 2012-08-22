#!/usr/bin/perl -w

use Cwd 'abs_path';
use File::Basename;
use Getopt::Std;
use Date::Simple;

my $options = ();
getopts("v", \%options);

&_verbose("Starting...");

chdir dirname(abs_path($0));

my %cfg = do('settings');
my @allowed = &_read_list('allow');
my @footprints = &_read_list('footprints');

$logs = '/var/log/httpd/www*access_log';
$grep = '/bin/grep';
$banCmd = '/sbin/iptables -A HTTPD -s %s -j DROP';
$findCmd = '/sbin/iptables -L HTTPD -n';

my %deny = ();
my @existing = `$findCmd`;

foreach my $fp (@footprints) {
	my @found = `$grep $fp $logs`;

	foreach my $r (@found) {
		chomp($r);
		my ($vhost) = $r =~ /httpd\/(.*?)-access_log/;
		my ($ip) = $r =~ /:(\d+\.\d+\.\d+\.\d+)\s-/;

		if (!$ip) {
			&_verbose("NO IP Found: $r");
			next;
		}

		if (!&_allowIp($ip)) {
			$deny{$ip}{$vhost}{$fp}++;
		}
		else {
			&_verbose("IP: $ip is allowed on '$fp'.");
		}
	}
}

foreach my $ip (keys %deny) {
	if (!&_alreadyDenied($ip)) {
		my $fwCmd = sprintf($banCmd, $ip);
		my $hostCount = scalar(keys %{$deny{$ip}});
		my $attackCount = 0;

		foreach my $host (keys %{ $deny{$ip} }) {
			foreach my $app (keys %{ $deny{$ip}{$host} }) {
				$attackCount += $deny{$ip}{$host}{$app};
			}
		}

		my $response = "IGNORED";

		if ($hostCount >= $cfg{'trigger'}{'minHosts'} || $attackCount >= $cfg{'trigger'}{'minAttacks'}) {
			`$fwCmd`;
			$response = "BANNED";
		}

		&_scan_log("$ip attacked $hostCount vhost(s) with $attackCount queries... $response");
	}
	else {
		&_verbose("$ip is already blocked, but found it in logs...");
	}
}

sub _allowIp($) {
	my ($ip) = @_;
	foreach (@allowed) {
		if ($ip =~ /$_/) {
			return 1;
		}
	}
	return 0;
}

sub _alreadyDenied($) {
	my ($ip) = @_;
	$found = grep /$ip/, @existing;
	return $found;
}

sub _timestamp {
        my $date = Date::Simple->new;

        my $mo = $date->month;
        $mo = "0" . $mo if length($mo) == 1;
        my $dy = $date->day;
        $dy = "0" . $dy if length($dy) == 1;

        my ($hr,$mn,$sc) = (localtime)[2,1,0];

        $hr = "0" . $hr if length($hr) == 1;
        $mn = "0" . $mn if length($mn) == 1;
	$sc = "0" . $sc if length($sc) == 1;

        return ($date->year, $mo, $dy, $hr, $mn, $sc);
}

sub _scan_log($) {
	my ($msg) = @_;
	my @ts = &_timestamp();
	my $date = sprintf("%d/%d/%d", $ts[1], $ts[2], $ts[0]);
	my $time = sprintf("%d:%d:%d", $ts[3], $ts[4], $ts[5]);
	print "$date - $time - $msg\n";
}

sub _verbose($) {
	my ($msg) = @_;
	if ($options{v}) {
		&_scan_log($msg);
	}
}

sub _read_list($) {
	my ($file) = @_;
	open(IN, "< $file") || die "Can't read config: " . $file;
	my @in = <IN>;
	close(IN);

	my @r = ();

	foreach my $i (@in) {
		chomp($i);
		next if $i =~ /^#/;	
		push @r, $i;
	}

	return @r;
}

&_verbose("Finished");
