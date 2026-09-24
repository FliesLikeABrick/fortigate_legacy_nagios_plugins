#!/usr/bin/perl
# This Plugin checks the status of Fortigate Firewalls
# Thanks to Gerrit Doornenbal for the original script.. 
# I just modded it heavily.

# Check for proper args....
if ($#ARGV <= 0){
&print_help();
}

my %status = ( 'UNKNOWN' => '-1',
    'OK'    => '0',
    'WARNING' => '1',
    'CRITICAL' => '2' );
my ($ip, $mode, $community, $modus, $warn, $crit, $performance) = pars_args();

@oidDescTest = (".1.3.6.1.4.1.12356.1.3", ".1.3.6.1.2.1.47.1.1.1.1.10.1");
until ($oidFound) {
foreach $oidDesc (@oidDescTest) {
  $snmpCommand = `/usr/bin/snmpwalk -v 2c -c $community $ip $oidDesc`;
  chomp $snmpCommand;

  if ($snmpCommand =~ "No Such Object") {
   # Do nothing
  } else {
   $oidFound = "yes";
   $descString = $snmpCommand;
  }
}
}

@descArray = split("\"", $descString);
$unitdesc = @descArray[-1];

@descArray = split(",", $unitdesc);
$unitdesc = @descArray[0];

@descArray = split(" ", $unitdesc);
$unitdesc = @descArray[0];


if ($mode =~ "cpu" && $unitdesc =~ m/200/i) {
$oid = ".1.3.6.1.4.1.12356.1.8";
} elsif ($mode =~ "cpu" && $unitdesc =~ m/80c/i) {
$oid = ".1.3.6.1.4.1.12356.101.4.1.3";
} elsif ($mode =~ "cpu") {
$oid = ".1.3.6.1.4.1.12356.101.4.1.3";
} elsif ($mode =~ "mem" && $unitdesc =~ m/200/i) {
$oid = ".1.3.6.1.4.1.12356.1.9";
} elsif ($mode =~ "mem" && $unitdesc =~ m/80c/i) {
$oid = ".1.3.6.1.4.1.12356.101.4.1.4";
} elsif ($mode =~ "mem") {
$oid = ".1.3.6.1.4.1.12356.101.4.1.4";
} elsif ($mode =~ "ses" && $unitdesc =~ m/200/i) {
$oid = ".1.3.6.1.4.1.12356.1.10";
} elsif ($mode =~ "ses" && $unitdesc =~ m/80c/i) {
$oid = ".1.3.6.1.4.1.12356.101.4.1.8";
} elsif ($mode =~ "ses") {
$oid = ".1.3.6.1.4.1.12356.101.4.1.8";
} else {
&print_help();
}

eval {
$snmpCommand = `/usr/bin/snmpwalk -v 2c -c $community $ip $oid`;
chomp $snmpCommand;
} or do {
system("clear");
print "\nOops! Your model doesn't seem to be supported by this script... Yet!\n\n";
print "If you want to help out, try running the following command (replace \"FGXXXXXXXXXXXXXX\" with your Fortigate's serial number):\n\n";
print " snmpwalk -v 2c -c public [FortiGate IP address] .1.3.6.1.4.1.12356 | grep -iR \"FGXXXXXXXXXXXXXX\"\n";
print "\n";
print "The OIDs for CPU usage and other stats are almost always found near an OID containing the unit's serial number.\n\n";
print "For example, here's the output I get:\n\n";
print " # snmpwalk -v 2c -c public 172.16.10.10 .1.3.6.1.4.1.12356 | grep -iR \"FGT80C1234567890\"\n";
print "  iso.3.6.1.4.1.12356.100.1.1.1.0 = STRING: \"FGT80C1234567890\"\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.2.1 = STRING: \"FGT80C1234567890\"\n\n";
print "Now, all I need is to find which OID branch contains the info I want.\nTo do this, I grab the OID of the first result...\n\n";
print " iso.3.6.1.4.1.12356.100.1.1.1.0\n\n";
print "... remove the last two digits...\n\n";
print " iso.3.6.1.4.1.12356.100.1.1\n\n";
print "... and use that with snmpwalk.\n\n";
print " # snmpwalk -v 2c -c public 172.16.10.10 iso.3.6.1.4.1.12356.100.1.1\n";
print "  iso.3.6.1.4.1.12356.100.1.1.1.0 = STRING: \"FGT80C1234567890\"\n\n";
print "Hmmm. Nothing useful here.\n\nLet's try the second value.\n\n";
print " iso.3.6.1.4.1.12356.101.13.2.1.1.2.1\n\n";
print "... remove the last two digits...\n\n";
print " iso.3.6.1.4.1.12356.101.13.2.1.1\n\n";
print "... and try that with snmpwalk!\n\n";
print " # snmpwalk -v 2c -c public 172.16.10.10 iso.3.6.1.4.1.12356.101.13.2.1.1\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.1.1 = INTEGER: 1\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.2.1 = STRING: \"FGT80C1234567890\"\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.3.1 = Gauge32: 99\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.4.1 = Gauge32: 72\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.5.1 = Gauge32: 19690\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.6.1 = Gauge32: 212\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.7.1 = Counter32: 4185780372\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.8.1 = Counter32: 2786324006\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.9.1 = Counter32: 0\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.10.1 = Counter32: 0\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.11.1 = \"\"\n";
print "  iso.3.6.1.4.1.12356.101.13.2.1.1.11.1 = No more variables left in this MIB View (It is past the end of the MIB tree)\n\n";
print "Ooohhh... I like this!\nThe third and fourth values turn out to be the values for CPU and RAM usage, respectively..\n\n";
print "So, try to find the values for your model, and I'll update the script with your findings.\n\n";

exit($status{"UNKNOWN"});
};

if ($mode =~ "cpu") {
@cpuArray = split(" ", $snmpCommand);
$usage = @cpuArray[-1]."%";
$usagestring = "CPU Usage";
} elsif ($mode =~ "mem") {
@memArray = split(":", $snmpCommand);
$usage = @memArray[-1]."%";
$usagestring = "Memory Usage";
} elsif ($mode =~ "ses") {
@sesArray = split(" ", $snmpCommand);
$usage = @sesArray[-1];
$warn = "1500";
$crit = "2000";
$usagestring = "Active IP Sessions";
}

$usage =~ s/^\s+//; # Remove leading...
$usage =~ s/\s+$//; # ...and trailing spaces

my $string_errors="";
my $state = "OK";

my $unitstate="OK";
if ($modus >= 1 )
{
if ($usage >= $warn)
{
  $unitstate="WARNING";
}
if ($usage >= $crit)
{
  $unitstate="CRITICAL";
}
}

my $string = $unitdesc . ": " . $unitstate;
$string = $string . ", $usagestring: " . $usage;

my $perfstring="";
if ( $performance eq "yes" )
{
$perfstring="| $usagestring=".$usage.";".$warn.";".$crit;
}
$string = $string.$perfstring;

if($string =~/uknw/){
$state = "UNKNOWN";
}
if($string =~/WARNING/){
$state = "WARNING";
}
if($string =~/down/){
$state = "CRITICAL";
}
if($string =~ m/critical/i){
$state = "CRITICAL";
}


print $string."\n";
exit($status{$state});


sub pars_args
{
my $ip    = "";
my $mode    = "";
my $community = "public";
my $modus   = "2";
my $warn  = "80";
my $crit  = "90";
my $performance = "yes";
while(@ARGV)
{
  if($ARGV[0] =~/^-H|^--host/)
  {
   $ip = $ARGV[1];
   shift @ARGV;
   shift @ARGV;
   next;
  }
  if($ARGV[0] =~/^-m|^--mode/)
  {
   $mode = $ARGV[1];
   shift @ARGV;
   shift @ARGV;
   next;
  }
  if($ARGV[0] =~/^-C|^--community/)
  {
   $community = $ARGV[1];
   shift @ARGV;
   shift @ARGV;
   next;
  }
  if($ARGV[0] =~/^-M|^--modus/)
  {
   $modus = $ARGV[1];
   shift @ARGV;
   shift @ARGV;
   next;
  }
if($ARGV[0] =~/^-w|^--warn/)
  {
   $warn = $ARGV[1];
   shift @ARGV;
   shift @ARGV;
   next;
  }
if($ARGV[0] =~/^-c|^--crit/)
  {
   $crit = $ARGV[1];
   shift @ARGV;
   shift @ARGV;
   next;
  }
if($ARGV[0] =~/^-f|^-F/)
  {
   $performance = "yes";
   shift @ARGV;
   next;
  }
}
return ($ip, $mode, $community, $modus, $warn, $crit, $performance);
}

sub print_help() {
print "\n";
print "Usage: check_fortigate_status -H host -m mode [-C community] [-M X] [-w XX] [-c XX]\n\n";
print "Options:\n\n";
print " -H, --host hostname (or IP address)\n";
print " Check interface on the indicated host.\n\n";
print " -m, --mode STRING\n";
print " What to check\n";
print " Valid values are:\n";
print "  cpu  Returns CPU usage\n";
print "  memory  Returns memory usage\n";
print "  sessions Returns the number of active IP sessions\n\n";
print " -C, --community STRING\n";
print " SNMP community string\n";
print " Default: public\n\n";
print " -M, --modus X\n";
print " 0: Just monitor, no alarms\n";
print " 1: Threshold excesses will cause alarms\n";
print " Default: 2\n\n";
print " -w, --warn XX\n";
print " Nagios warning threshold\n";
print " Percent value for \"memory\" and \"cpu\" modes\n";
print " Default: 80%\n";
print " Integer value for \"sessions\" mode\n";
print " Default: 1500\n\n";
print " -c, --crit XX\n";
print " Nagios critical threshold\n";
print " Percent value for \"memory\" and \"cpu\" modes\n";
print " Default: 90%\n";
print " Integer value for \"sessions\" mode\n";
print " Default: 2000\n";
#print " -F Also giving performance data output.\n\n";
#print "This plugin checks certain performance stats and gives the current utilization.\n\n";

exit($status{"UNKNOWN"});
}
