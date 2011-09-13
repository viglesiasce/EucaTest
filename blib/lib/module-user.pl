#!/usr/bin/perl
use strict;
use warnings;

use EucaTest;

### SETUP TEST CONSTRUCT WITH DESIRED HOST and other otional params

# 

my $clusterid = "PARTI00";

my $host = $ARGV[0];

my $local = EucaTest->new();
my $clc =  EucaTest->new({host => $host});


$clc->set_credpath($clc->get_cred("eucalyptus", "admin"));

my $localcred =  $clc->download_cred();

$local->sys("cat $localcred/eucarc  | grep -v EUCA_KEY_DIR= > $localcred/eucarc.tmp");
$local->sys("echo EUCA_KEY_DIR=$localcred > $localcred/eucarc.dir; cat $localcred/eucarc.tmp >> $localcred/eucarc.dir; mv $localcred/eucarc.dir $localcred/eucarc");

my $time= time();
$local->set_credpath($localcred);
$local->sys("euca-describe-volumes");

my @volumes = ();
my $maxVol = $ARGV[1];

for(my $volNum = 0; $volNum < $maxVol; $volNum++){
	push ( @volumes, $local->create_volume($clusterid, {size=> 1}) );
}

sleep 10;

foreach my $vol (@volumes){
	$local->delete_volume($vol);
}



exit;
