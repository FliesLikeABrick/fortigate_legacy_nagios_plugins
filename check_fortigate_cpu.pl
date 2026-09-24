#!/usr/bin/perl
# This  Plugin checks the CPU utilization Fortigate Firewalls 
# Tested on FG200A, FG200B, FG80C, Software v4MR2P2, v4MR3P1
# 
# Copyright (c) 2009 Gerrit Doornenbal, g(dot)doornenbal(at)hccnet(dot)nl 
# Many thanks to Sascha Tentscher , who provided a good example 
# with his 3com plugin!
#
# Changelog:
#   23 jan 2009	Initial Release, monitoring IPSEC and SSL-VPN
#	25 mar 2009	Added feature to disable monitoring, just for counting 
#				number of IPSEC connections
#   10 nov 2010	Numerous perl coding errors solved, added SNMP availabity check 
#               and VPN type choice for ipsec and ssl. 
#   8 jul 2011	Heavily modified by Brantley Hobbs to work with Fortinet 
#				firmware v4.0MR2 and higher.
#   2 aug 2011  Minor mods + added feature to get performance data.
#
# This program is free software; you can redistribute it and/or 
# modify it under the terms of the GNU General Public License 
# as published by the Free Software Foundation; either version 2 
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
# GNU General Public License for more details.
#
# If you wish to receive a copy of the GNU General Public License, 
# write to the Free Software Foundation, Inc., 
# 59 Temple Place - Suite 330, Boston, MA 02111-130

use strict;
use Net::SNMP;

# Check for proper args....
if ($#ARGV <= 0){
  &print_help();
}

# Initialize variables....
my $net_snmp_debug_level = 0x0;											# See http://search.cpan.org/~dtown/Net-SNMP-v6.0.1/lib/Net/SNMP.pm#debug()_-_set_or_get_the_debug_mode_for_the_module
																		# for more information.
my %status = (	'UNKNOWN'  => '-1',										# Enumeration for the output Nagios states
				'OK'       => '0',
				'WARNING'  => '1',
				'CRITICAL' => '2' );
my ($ip, $community, $modus, $warn, $crit, $performance) = pars_args();	# Parse out the arguments...
my ($session, $error) = get_snmp_session($ip, $community);				# Open an SNMP connection...
my $oid_unitdesc = ".1.3.6.1.2.1.1.1.0";								# Location of Fortinet device description...
my $oid_CPUUtil = ".1.3.6.1.4.1.12356.101.4.1.3.0"; 					# Location of Fortinet firewall CPU utilization
my $string_errors="";
my $state = "OK";

# Check SNMP connection and get the description of the device...
my $unitdesc  = get_snmp_value($session, $oid_unitdesc);

my $cpu = get_snmp_value($session, $oid_CPUUtil);

# Close the connection
close_snmp_session($session);  

#Set Unitstate
my $unitstate="OK";
if ($modus >= 1 )
{
	if ($cpu >= $warn)
	{
		$unitstate="WARNING";  
	}
	if ($cpu >= $crit)
	{
		$unitstate="CRITICAL";  
	}
}

# Write an output string...
my $string = $unitdesc . ": " . $unitstate; 
$string = $string . ", Current CPU Utilization: " . $cpu ."%"; 

# Create performance data
my $perfstring="";
if ( $performance eq "yes" ) 
	{
	$perfstring="| CPU-usage=".$cpu."%;".$warn.";".$crit;
	}
$string = $string.$perfstring;	

# Check to see if the output string contains either "unkw", "WARNING" or "down", and set an output state accordingly...
if($string =~/uknw/){
	$state = "UNKNOWN";
}
if($string =~/WARNING/){
	$state = "WARNING";
}
if($string =~/down/){
	$state = "CRITICAL";
}

#Emit the output and exit with a return code matching the state...
print $string."\n";
exit($status{$state});

########################################################################
##  Subroutines below here....
########################################################################
sub get_snmp_session{
  my $ip        = $_[0];
  my $community = $_[1];
  my ($session, $error) = Net::SNMP->session(
             -hostname  => $ip,
             -community => $community,
             -port      => 161,
             -timeout   => 1,
             -retries   => 3,
			 -debug		=> $net_snmp_debug_level,
			 -version	=> 2,
             -translate => [-timeticks => 0x0] #schaltet Umwandlung von Timeticks in Zeitformat aus
              );
  return ($session, $error);
}

sub close_snmp_session{
  my $session = $_[0];
  
  $session->close();
}

sub get_snmp_value{
	my $session = $_[0];
	my $oid     = $_[1];
	my (%result) = %{get_snmp_request($session, $oid) or die ("SNMP service is not available on ".$ip) }; 
	return $result{$oid};
}

sub get_snmp_request{
  my $session = $_[0];
  my $oid     = $_[1];
  return $session->get_request( $oid );
}

sub get_snmp_table{
  my $session = $_[0];
  my $oid     = $_[1];
  return $session->get_table(	
					-baseoid =>$oid
					); 
}

sub pars_args
{
  my $ip        = "";
  my $community = "public"; 
  my $modus     = "2";
  my $warn		= "80";
  my $crit		= "90";
  my $performance = "no";
  while(@ARGV)
  {
    if($ARGV[0] =~/^-H|^--host/) 
    {
      $ip = $ARGV[1];
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
  return ($ip, $community, $modus, $warn, $crit, $performance); 
} 

sub print_help() {
  print "Usage: check_fortigate_cpu -H host -C community\n";
  print "Options:\n";
  print " -H --host STRING or IPADDRESS\n";
  print "   Check interface on the indicated host.\n";
  print " -C --community STRING\n";
  print "   Community-String for SNMP. (default public)\n";
  print " -M --modus default = 2\n";
  print "   0: Just monitor, no alarms\n";
  print "   1: CPU utilization excesses will cause alarms\n";
  print " -w --warn NAGIOS warn level in percent (default 80%)\n";
  print " -c --crit NAGIOS crit level in percent (default 90%)\n";
  print " -F Also giving performance data output.\n\n";
  print "This plugin checks CPU utilization and gives\nthe current utilization.\n\n";
  
  exit($status{"UNKNOWN"});
}
