package EucaTest;

use 5.000003;
use strict;
use warnings;

use Net::OpenSSH;
require Exporter;
#use Data::Dumper;


our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
# This allows declaration	use EucaTest ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw( test_name fail pass
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';
my $exit_on_fail = 0;
my $fail_count = 0;
our $ofile = "ubero";
my $CLC_INFO = {};
my @running_log;
open(STDERR, ">&STDOUT");
sub new{
	my $ssh;
	my $class = shift;
	my $opts = shift;
	my $host = $opts->{'host'};
	my $keypath = $opts->{'keypath'};
	### IF we are going to a remote server to exec commands
	if( defined $host ){
		chomp $host;
		print "Creating an SSH connection to $host\n";
		## are we authenticating with keys or with password alone
		if( defined $keypath){
			chomp $keypath;
			 test_name("Creating a keypair authenticated SSH connection to $host");
			$ssh =  Net::OpenSSH->new( $host, key_path => $keypath ,  master_opts => [-o => "StrictHostKeyChecking=no" ]  );
			$ssh->error and
   			fail( $ssh->error);
		}else{
			test_name( "Creating a password authenticated SSH connection to $host");
			$ssh =  Net::OpenSSH->new($host,  master_opts => [-o => "StrictHostKeyChecking=no" ] );
			$ssh->error and
   			fail( $ssh->error);
		}
	}else{ 
		print "Creating a LOCAL connection\n";
		undef $ssh;
	}
	
	my $credpath = $opts->{'credpath'};
	if( !defined $credpath){
		 $credpath = "";
	}
	my $delay = $opts->{'delay'};
	if( !defined $delay){
		 $delay = 0;
	}
	
	my $timeout = $opts->{'timeout'};
	if( !defined $timeout){
		$timeout = 120;
	}
	
	my $eucadir = $opts->{'eucadir'};
	if( !defined $eucadir){
		$eucadir = "/opt/eucalyptus";
	}
	
	my $verify_level = $opts->{'verifylevel'};
	if( !defined $verify_level){
		$verify_level = "10";
	}
	
	my $toolkit = $opts->{'toolkit'};	
	if( !defined $toolkit){
		$toolkit = "euca-";
	}
	$exit_on_fail = $opts->{'exit_on_fail'};	
	if( !defined $exit_on_fail){
		$exit_on_fail = 0;
	}
	my $self  = { SSH => $ssh , CREDPATH => $credpath, TIMEOUT => $timeout, EUCALYPTUS => $eucadir,  VERIFY_LEVEL=> $verify_level, TOOLKIT => $toolkit, DELAY => $delay, EXIT_ON_FAIL => $exit_on_fail, FAIL_COUNT=> $fail_count};
	bless $self;
	
	if( defined $ssh && $self->get_credpath eq ""){
		my $admin_credpath = $self->get_cred("eucalyptus", "admin");
		
		if($admin_credpath !~ /eucarc/ ){
			fail("Failed to download credentials");
		}else{
			$self->set_credpath($admin_credpath);
		}
	}
	
	return $self;
}

sub fail {
  my($message) = @_;
  
  push(@running_log, "^^^^^^[TEST_REPORT] FAILED - $message^^^^^^\n");
  print("^^^^^^[TEST_REPORT] FAILED - $message^^^^^^\n");
  $fail_count++;
  if ($exit_on_fail){
  	exit(1);
  }
}

# Print formatted success message
sub pass {
  my($message) = @_;
  push(@running_log, "^^^^^^[TEST_REPORT] PASSED - $message^^^^^^\n\n");
  print("^^^^^^[TEST_REPORT] PASSED - $message^^^^^^\n\n");
  return 0;
}

# Print test case name (ie a description of the following steps)
sub test_name {
  my($name) = @_;
  push(@running_log, "******[TEST_REPORT] ACTION - $name ******\n");
  print("******[TEST_REPORT] ACTION - $name ******\n");
}

sub log{
	my $self =shift;
	my $message = shift;
	push(@running_log, "$message");
	return 0;
}
sub tee{
	my $self =shift;
	my $message = shift;
	push(@running_log, "$message");
	print($message);
	return 0;
}

sub get_fail_count{
	my $self = shift;
	return $fail_count;
}
sub get_verifylevel{
	my $self = shift;
	return $self->{VERIFYLEVEL};
}
sub set_verifylevel{
	my $self = shift;
	my $level = shift;
	$self->{VERIFYLEVEL}= $level;
	return 0;
}
sub get_delay{
	my $self = shift;
	return $self->{DELAY};
}
sub set_delay{
	my $self = shift;
	my $delay = shift;
	$self->{DELAY}= $delay;
	return 0;
}
sub get_toolkit{
	my $self = shift;
	return $self->{TOOLKIT};
}
sub set_toolkit{
	my $self = shift;
	my $toolkit = shift;
	$self->{TOOLKIT}= $toolkit;
	return 0;
}

sub get_ssh{
	my $self = shift;
	return $self->{SSH};
}

sub set_ssh{
	my $self = shift;
	my $ssh = shift;
	$self->{SSH} = $ssh;
	return 0;
}

sub get_timeout{
	my $self = shift;
	return $self->{TIMEOUT};
}

sub set_timeout{
	my $self = shift;
	my $timeout = shift;
	$self->{TIMEOUT} = $timeout;
	return 0;
}
sub get_credpath{
	my $self = shift;
	return $self->{CREDPATH};
}

sub set_credpath{
	my $self = shift;
	my $credpath = shift;
	$self->sys("cat $credpath/eucarc  | grep -v EUCA_KEY_DIR= > $credpath/eucarc.tmp");
    $self->sys("echo EUCA_KEY_DIR=$credpath > $credpath/eucarc.dir; cat $credpath/eucarc.tmp >> $credpath/eucarc.dir; mv $credpath/eucarc.dir $credpath/eucarc");
	
	$self->{CREDPATH} = $credpath;

	return 0;
}

sub download_keypair{
	my $self = shift;
	my $keypair = shift;
	my @rsa_pub = `cat ~/.ssh/id_rsa.pub`;
	$self->sys("echo \'@rsa_pub\' >> ~/.ssh/authorized_keys");
	my $cmd = "scp root\@$CLC_INFO->{'QA_IP'}:$keypair.priv .";
	my $keypair_text = `$cmd`;
	return $keypair_text;
	
}
sub cleanup{
	my $self = shift;
 	my $tc_id = shift;
 	my $tplan_id = shift;
 	if( defined $tc_id && defined $tplan_id){
 		
 		$self->update_testlink($tc_id, $tplan_id);
 	}
	$self->sys("rm -f *.priv *.log");
    $self->sys("rm -rf $self->{CREDPATH}");
    my @rm_log = `rm *.log`;
	return 0;
}
sub clear_log{
	my $self = shift;
	@running_log = ();
}

sub update_testlink{
	my $self =shift;
	my $tc_id = shift;
	my $tplan_id = shift;
	my $status = shift;
	my $build = shift;
	
	### Get status from total fail_count
	if( !defined $status){
		$status = 'f';
		if( $fail_count == 0){
 			$status= "p";
 		}
	}
	 
 		
 		my $notes ="";
 		my $platform = 1;
 		
 		if( defined $CLC_INFO->{"QA_DISTRO"}) {
 			    my $qa_distro =  $CLC_INFO->{"QA_DISTRO"};
				my $qa_distro_ver = $CLC_INFO->{'QA_DISTRO_VER'} ;
				my $qa_arch = $CLC_INFO->{'QA_ARCH'};
				my $qa_source = $CLC_INFO->{'QA_SOURCE'} ;
				my $qa_roll =$CLC_INFO->{'QA_ROLL'} ;
				my $qa_ip =$CLC_INFO->{'QA_IP'} ;
				
			#[ID: 1 ] CentOS 5 64bit 		
			#[ID: 2 ] CentOS 5 32bit 		
			#[ID: 3 ] RHEL 5 32bit 		
			#[ID: 4 ] Ubuntu Lucid 64bit 				
			#[ID: 5 ] Ubuntu Lucid 32bit 		
			#[ID: 7 ] RHEL 5 64bit 		
			#[ID: 8 ] Debian Squeeze 64bit 	
			if( !defined $CLC_INFO->{'NODE_DISTRO'}  ){
				$CLC_INFO->{'NODE_DISTRO'} = "unknown";
			}	
			if(  $CLC_INFO->{'NODE_DISTRO'} =~ /VMWARE/i  ){
				if( $qa_distro =~ /CENTOS/i ){
					$platform = 12;
				}elsif( $qa_distro =~ /UBUNTU/i ){
					$platform = 11;
				}
			}
			elsif( ($qa_distro =~ /CENTOS/i) && ( $qa_arch =~ /64/)){
				$platform = 1;
			}
			elsif( ($qa_distro =~ /CENTOS/i) && ( $qa_arch =~ /32/)){
				$platform = 2;
			}
			elsif( ($qa_distro =~ /RHEL/i) && ( $qa_arch =~ /64/)){
				$platform = 7;
			}
			elsif( ($qa_distro =~ /RHEL/i) && ( $qa_arch =~ /32/)){
				$platform = 3;
			}
			elsif( ($qa_distro =~ /UBUNTU/i) && ( $qa_arch =~ /64/)){
				$platform = 4;
			}
			elsif( ($qa_distro =~ /UBUNTU/i) && ( $qa_arch =~ /32/)){
				$platform = 5;
			}
			elsif( ($qa_distro_ver =~ /DEBIAN/i) && ( $qa_arch =~ /64/)){
				$platform = 8;
			}
			
			
			
			
 			#push(@running_log, "IP $qa_ip [Distro $qa_distro, Version $qa_distro_ver, ARCH $qa_arch] is built from $qa_source as Eucalyptus-$qa_roll\n");
 			
 		}
 		### Add the entire config file to the top of the result
 		if( defined $CLC_INFO->{"TEST_NAME"}){
 			my $artifacts_link = "http://10.1.1.210/test_space/". $CLC_INFO->{"TEST_NAME"} . "/" . $CLC_INFO->{"UNIQUE_ID"} ;
 			$artifacts_link = "<a href=\"" . $artifacts_link . "\" style=\"color:blue;font-size:20px;\" target=\"_blank\">Go to Artifacts</a> ";
 		   $CLC_INFO->{"INPUT_FILE"} =  $artifacts_link .  "<br>" .$CLC_INFO->{"INPUT_FILE"};
 		   $CLC_INFO->{"INPUT_FILE"} =~ s/\n/<br>/g;
 		   
 		}
 		$CLC_INFO->{"INPUT_FILE"} = "##################### TEST SETUP #####################\n" . $CLC_INFO->{"INPUT_FILE"} . "\n\n\n##################### TEST OUTPUT #####################\n";
 		
 		### Remove \n and replace with HTML newline character <br>
 		
 		foreach my $line (@running_log){
 			if($line =~ /fail/i || $line =~ /error/i ){
 				#$status = 'f';
				$line = "<font color=\"red\" size=\"4\">$line</font>";
			}elsif( $line =~ /\[.*].*/ ){
				$line = "<font color=\"blue\" size=\"2\">$line</font>";
			}
			
 			$line =~ s/\n/<br>/g;
 			
 		}
 		#unshift(@running_log ,$CLC_INFO->{"INPUT_FILE"} );
 		##
 		my $run_file = "run-$tc_id-" . time() .".log";
 		open FILE, ">", "$run_file" or die $!;
 		print FILE"@running_log";
 		close FILE;
 		my @scp_result = `scp $run_file root\@192.168.51.187:artifacts/$run_file`;
 		#print "@scp_result";
 		
 		
 		### IF a different testplan is in the memo update that one
 		if ( defined $CLC_INFO->{"TESTPLAN_ID"} ){
 			$tplan_id = $CLC_INFO->{"TESTPLAN_ID"};
 		}
 		$build = "other";
 		if ( defined $CLC_INFO->{'BZR_REVISION'}){
 			$build = $CLC_INFO->{'BZR_REVISION'};
 		}
 		my @build_response = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'./testlink/update_build.pl testplanid=322 \"$build\"'");
 		my $build_id = $build_response[0];
 		chomp($build_id);
 		my @exec_resp = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'./testlink/update_testcase.pl artifacts/$run_file testcaseexternalid=$tc_id,testplanid=$tplan_id,status=$status,buildid=$build_id,platformid=$platform\'");
 		
 		
 	   ##UPLOADING THE TC RESULT WILL RETURN ME THE EXEC ID
 		
 		
 		$self->sys("rm $run_file");
 		print "Updated Testcase: $tc_id in Testplan $tplan_id with result $status on build $build_id which is revno $build and exec_id \n";
 		return $exec_resp[0];
}

sub attach_artifacts{
	my $self = shift;
	my $exec_id = shift;
	if(!defined $exec_id){
		fail("No exec id provided to attach artifacts");
		return -1;
	} 
	chomp $exec_id;
	## SEND THE ARTIFACTS TO THE REMOTE MACHINE
	my @mkdir_response = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'mkdir artifacts/$exec_id\'");
	my @scp_artifacts_result = `scp ../artifacts/*.out root\@192.168.51.187:artifacts/$exec_id`;
 	
	
	## LOOK FOR ALL THE REMOTE ARTIFACTS UPLOADED 
	my @remote_artifacts = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'ls artifacts/$exec_id\'");
	#print "@remote_artifacts";
	foreach my $artifact (@remote_artifacts){
		chomp $artifact;
		my @exec_resp = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'./testlink/upload_attachment.pl artifacts/$exec_id/$artifact filename=$artifact,filetype=text/html,executionid=$exec_id\'");
	
	}
	
	##DELETE ARTICACTS AFTER UPLOAD
	my @remove_artifacts = $self->sys("ssh root\@192.168.51.187 -o StrictHostKeyChecking=no \'rm -rf artifacts/$exec_id\'");
	return 0;
}

sub set_clc_info{
	my $self = shift;
	$CLC_INFO = shift;
	return 0;	
}
sub timestamp{
	 my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)=localtime(time);
     my $timestamp =  sprintf ("%02d-%02d %02d:%02d:%02d\n",$mon+1,$mday,$hour,$min,$sec);
	chomp($timestamp);
	return $timestamp;  
}

sub sys {
  my $self = shift;
  my $cmd = shift;
  my $timeout = shift;
  my $original_cmd = $cmd;
  if( $self->{CREDPATH} ne ""){
		$cmd = ". " . $self->{CREDPATH} ."/eucarc && " . $cmd;
  }

  sleep($self->{DELAY});
  my $systimeout;
  if(defined $timeout){
  	$systimeout = $timeout;
  }else{
  	$systimeout = $self->{TIMEOUT};
  }
  
  my @output;
  	# Return and print failure 
  	$SIG{ALRM} = sub { die "alarm\n"; };
	eval {		
    alarm($systimeout);
      
       my $timestamp =  timestamp();
  		
	if( defined  $self->{SSH} ){
		 my $rem_host = $self->{SSH}->get_host();
		 my $rem_user = $self->{SSH}->get_user();
		 $self->tee("[$rem_user\@$rem_host - $timestamp] $original_cmd\n");
		  @output =  $self->{SSH}->capture( $cmd);
		 
 		  #$self->{SSH}->error and fail( "SSH ERROR: " . $self->{SSH}->error);
		 
	}else{
		
		$self->tee("[LOCAL - $timestamp] $original_cmd\n");
		@output = `$cmd`;
		
	}
	alarm(0);
		
	};
	if ($@) {
		die unless $@ eq "alarm\n"; # propagate unexpected errors
		# timed out
		$self->tee("@output\n"); 
		fail("Timeout occured after $systimeout seconds\n"); 
		
		return @output;
	}
	else {		# didn't
		$self->tee("@output\n");
		return @output;
    
	}
	
}

sub read_input_file{
	my $self = shift;
	my $filename = shift;
	my $is_memo = 0;
	my $memo = "";
	my %CONFIG;
	open( INPUT, "< $filename" ) || die $!;
 
	my $line;
	while( $line = <INPUT> ){
		$CONFIG{'INPUT_FILE'} .= $line;
		chomp($line);
		if( $is_memo ){
			if( $line ne "END_MEMO" ){
				
				###LOOK FOR THE TESTPLAN_ID IN THE MEMO
				if( $line =~ /^TESTPLAN_ID/){
					my @testplan_id = split(/=/, $line);
					$CONFIG{'TESTPLAN_ID'} = $testplan_id[1];
				}
				
				### ADD THIS LINE TO THE MEMO
				$memo .= $line . "\n";
			};
		} ;
			if( $line =~ /^BZR_REVISION/){
					my @bzr_rev = split(/\s+/, $line);
					$CONFIG{'BZR_REVISION'} = $bzr_rev[1];
				}
			if( $line =~ /^TEST_NAME/){
					my @test_name = split(/\s+/, $line);
					$CONFIG{'TEST_NAME'} = $test_name[1];
				}
			if( $line =~ /^UNIQUE_ID/){
					my @unique_id = split(/\s+/, $line);
					$CONFIG{'UNIQUE_ID'} = $unique_id[1];
				}
			if( $line =~ /^NETWORK/){
					my @network = split(/\s+/, $line);
					$CONFIG{'NETWORK'} = $network[1];
				}				
				
        	if( $line =~ /^([\d\.]+)\t(.+)\t(.+)\t(\d+)\t(.+)\t\[(.+)\]/ ){
			my $qa_ip = $1;
			my $qa_distro = $2;
			my $qa_distro_ver = $3;
			my $qa_arch = $4;
			my $qa_source = $5;
			my $qa_roll = $6;
			
			my $this_roll = lc($6);
			if( $this_roll =~ /clc/ ){
				print "\n";
				$CONFIG{'QA_DISTRO'} = $qa_distro;
				$CONFIG{'QA_DISTRO_VER'} = $qa_distro_ver;
				$CONFIG{'QA_ARCH'} = $qa_arch;
				$CONFIG{'QA_SOURCE'} = $qa_source;
				$CONFIG{'QA_ROLL'} = $qa_roll;
				$CONFIG{'QA_IP'} = $qa_ip;
					print "IP $qa_ip [CLC Distro: $qa_distro CLC Version: $qa_distro_ver CLC ARCH $qa_arch] is built from $qa_source as Eucalyptus-$qa_roll\n";
			}elsif( $this_roll =~ /nc/ ){
				
				$CONFIG{'NODE_DISTRO'} = $qa_distro;
				$CONFIG{'NODE_DISTRO_VER'} = $qa_distro_ver;
					print "IP $qa_ip [NC Distro: $qa_distro NC Version: $qa_distro_ver NC ARCH $qa_arch] is built from $qa_source as Eucalyptus-$qa_roll\n";
			}
		
		}elsif( $line =~ /^MEMO/ ){
			$is_memo = 1;
		}elsif( $line =~ /^END_MEMO/ ){
			$is_memo = 0;
		};
	};	

	close(INPUT);

	$CONFIG{'QA_MEMO'} = $memo;
	
	$CLC_INFO =\%CONFIG;
 
	return \%CONFIG;
};

sub piperun {
	my $self = shift;
    my $cmd = shift @_;
    my $pipe = shift @_;
    my $uberofile = shift @_ || "/tmp/uberofile.$$";
    my $pipestr = "";

    if ($pipe) {
	$pipestr = "| $pipe";
    }
    
    my @buf = $self->sys("$cmd > /tmp/tout.$$ 2>&1");
    my $retcode = ${^CHILD_ERROR_NATIVE};

    chomp(my $buf = `cat /tmp/tout.$$ $pipestr`);
    my $pipecode = system("cat /tmp/tout.$$ $pipestr >/dev/null 2>&1");

    system("echo '*****' >> $uberofile");
    system("echo CMD=$cmd >> $uberofile");
    my $rc = system("cat /tmp/tout.$$ >> $uberofile");
    unlink("/tmp/tout.$$");

    sleep(1);
    return($retcode, $pipecode, $buf);
}


sub get_cred {
  my($self, $account, $user) = @_;
  my $cred_dir = "eucarc-$account-$user";
  $self->sys("mkdir " . $cred_dir);
  
  if( !$self->found("ls", qr/$cred_dir/)){
		fail("Unable to make directory: $cred_dir");
		return -1;
	}
  
  my $cmd = $self->{EUCALYPTUS} . "/usr/sbin/euca_conf --get-credentials $cred_dir/euca.zip --cred-account $account --cred-user $user";
  ##Get credentials as a zip file in $cred_dir
  $self->sys($cmd);
  
   if( !$self->found("ls $cred_dir", qr/euca.zip/)){
		fail("Unable to make credentials");
		return -1;
	}
  
  ##Change to that directory and unzip the credentials
  $self->sys("cd $cred_dir; unzip -o euca.zip");
 
  return "$cred_dir";
}

sub download_cred{
	my $self = shift;
	my $create_dir = `mkdir $self->{CREDPATH}`;
	print $create_dir;
	$self->{SSH}->scp_get({glob => 1}, $self->{CREDPATH} . "/*", "$self->{CREDPATH}");
	return $self->{CREDPATH};
}

sub send_cred{
	my $self = shift;
	my $host = shift;
	$self->sys("scp -r $self->{CREDPATH} $host");
	return $self->{CREDPATH};	
}

sub add_keypair{
	my $self = shift;
	my $keyname = shift;
	my $filepath = "$keyname.priv";
	$self->sys("$self->{TOOLKIT}add-keypair $keyname | grep -v KEYPAIR > $filepath");
	sleep 1;
	#If the private key file exists and the first line starts with BEGIN RSA PRIVATE KEY
	my @lsresult = $self->sys("ls $filepath");
	
	if ( $lsresult[0] !~ m/cannot access/) {
 		
 		my @KEYFILE = $self->sys("cat $filepath");
 		if( $KEYFILE[0] =~ /BEGIN RSA PRIVATE KEY/ ){
 			pass("Correctly added keypair $keyname");
 			$self->sys("chmod 0600 $filepath");
 			return $keyname;
 		}
 		else{
 			fail("No key inside private key file");
 			my @key = $self->sys("cat $filepath");
 			print "Key File Contains:\n@key";
 			return -1;
 		}
 	} 
 	else{
 		fail( "Keypair file not found at $filepath");
 		return -1;
 	}
 	
		
}

sub delete_keypair{
	my $self = shift;
	my $keyname = shift;
	my $filepath = "$keyname.priv";
	my @output = $self->sys("$self->{TOOLKIT}delete-keypair $keyname");
	## Check the first line of output for KEYPAIR
	if($output[0] =~ /KEYPAIR/){
			
			### THIS will falsely detect keypairs that contain the $keyname #################3
			#my @output = $self->sys("euca-describe-keypairs | grep $keyname");
			#ENSURE THE KEYPAIR NO LONGER EXISTS
			
			if( !$self->found("$self->{TOOLKIT}describe-keypairs", qr/$keyname/) ){
				pass("Deleted keypair $keyname");
				$self->sys("rm -f $filepath");
				return @output;
			}else{
				fail("Keypair is still present or a keypair with this keypairs name embedded exists");
				return @output;
			}
			
	}else{
		fail("Delete keypair command did not return the keypair which was deleted");
		return @output;
	}
}

sub get_keypair{
	my $self = shift;
	my $keyname = shift;
	my $filepath = "$keyname.priv";
	my @key = $self->sys("cat $filepath");
	return "@key";
}

sub found {
  my($self, $list_cmd, $to_search) = @_;
  my $found = 0;
  for my $item ($self->sys($list_cmd )) {
    if ($item =~ /$to_search/) {
      $found = 1;
    }
  }
  return $found;
}

sub add_group{
	my $self = shift;
	my $groupname = shift;
	my $rule = shift;
	
	
	
	### CHECK IF THE GROUP EXISTS
	my @desc_groups = $self->sys("$self->{TOOLKIT}describe-groups $groupname");
	
	### IF IT DOES NOT EXIST CREATE IT 
	if( @desc_groups < 1){
		my @add_group = $self->sys("$self->{TOOLKIT}add-group $groupname -d $groupname");
		if($add_group[0] =~ /GROUP/){
			pass("Added group $groupname successfully");
		}
		else{ 
			fail("Unable to add group $groupname");
			return -1;
		}
	}else{
		pass("Group $groupname already exists not creating");
	}
	
	
	
	### IF THE USER DOES NOT PROVIDE A RULE CREATE THE GROUP with p22 and icmp
	if( !defined $rule ){
		
		my @auth_icmp = $self->sys("$self->{TOOLKIT}authorize $groupname -P icmp");
		if($auth_icmp[0] =~ /GROUP/){
			pass("Added ICMP authorization for $groupname successfully");
		}
		else{ 
			fail("Unable authorize group $groupname for ICMP");
			return -1;
		}
		
		my @auth_ssh  = $self->sys("$self->{TOOLKIT}authorize $groupname -p 22");
		if($auth_ssh[0] =~ /GROUP/){
			pass("Added SSH authorization for $groupname successfully");
		}
		else{ 
			fail("Unable authorize group $groupname for SSH");
			return -1;
		}
	}else{
		my @auth_rule = $self->sys("$self->{TOOLKIT}authorize $groupname $rule");
		if($auth_rule[0] =~ /GROUP/){
			pass("Added $rule authorization for $groupname successfully");
		}
		else{ 
			fail("Unable authorize group $groupname for $rule");
			return -1;
		}
	}
	
	return ($groupname);
}


sub delete_group{
	my $self = shift;
	my $groupname = shift;
	my $ip = shift;
	my @add_group = $self->sys("$self->{TOOLKIT}delete-group $groupname");
	if($add_group[0] =~ /GROUP/){
		pass("Deleted group $groupname successfully");
		return @add_group;
	}
	else{ 
		fail("Unable to delete group $groupname");
		return -1;
	}
}

sub allocate_address{
	my $self = shift;
	my @output = $self->sys("$self->{TOOLKIT}allocate-address");
	if($output[0] =~ /ADDRESS/){
		my @ip = split(' ', $output[0]);
		pass("Address $ip[1] allocated");
		return $ip[1];
	}
	else{
		fail("Unable to allocate address");
		return -1;
	}
	
}

sub release_address{
	my $self = shift;; 
	my $address = shift;
	
	my @output = $self->sys("$self->{TOOLKIT}release-address $address");
	if($output[0] =~ /ADDRESS/){
		my @ip = split(' ', $output[0]);
		if( $ip[1] =~ $address){
			pass("Address $ip[1] released");
			return $ip[1];
		}
		else{
			fail("Wrong address released");
			return -1;
		}		
	}
	else{
		fail("Unable to release address $address");
		return -1;
	}
}

sub get_emi{
	my $self = shift;
	my $filter = shift;
	my $cmd = "$self->{TOOLKIT}describe-images | grep -v windows | grep available | grep emi";
	if( defined $filter){
		$cmd .= " | grep $filter";
	}
	my @output = $self->sys($cmd);
	if( @output < 1){
		fail("No EMI found");
		return -1;
	}
	if($output[0] =~ /emi/){
		my @emi = split(' ', $output[0] );
		pass("Found EMI $emi[1]");
		return $emi[1];	
	}
	else{
		fail("No EMIs found");
		return -1;
	}
	
}

sub discover_emis {
    my $self = shift;
   
    my $cmd = "$self->{TOOLKIT}describe-images";
    my ($crc, $rc, $buf) = piperun($cmd, "grep IMAGE | grep -i 'mi-' | awk '{print \$2}'", "$ofile");
    if ($rc) {
		fail("Failed in running describe images when trying to discover EMIs");
		return -1;
    }
    my @emi_list= ();
    my @output = split(/\s+/, $buf);
    foreach my $emi (@output) {
		if (!$emi  || $emi eq "" || !($emi =~ /.*mi-.*/)) {
	    	print "WARN: emis=@output, emi=$emi\n";
		} 
		else {
	    	push(@emi_list, $emi);
		}
    }

    return @emi_list;
}

### TAKES in the url to a euca packaged image
sub download_euca_image{
	my $self = shift;
	my $source = shift;
	my $dest = shift;
	
	#Download the tarball
	if( !defined $source || !defined $dest){
		fail("Base URL or image name not defined");
		return -1;
	}
	$self->sys("wget $source$dest", 600);
	if( !$self->found("ls", qr/$dest/)){
		fail("Unable to download file");
		return -1;
	}else{
		print "Finished downloading file: $dest\n";
	}
	
	## Untar the bundle
	$self->sys("tar xzf $dest");
	my @dir = split(/.tgz/, $dest);
	if( !$self->found("ls $dir[0]", qr/.img/)){
		fail("Unable to untar file");
		return -1;
	}else{
		print "Finished untarring bundle: $dest\n";
	}
	
	return $dir[0];
}

sub upload_euca_image{
	my $self = shift;
	my $dir = shift;
	my $hypervisor = shift;
	my $prefix = shift;
	if( !defined $dir || !defined $hypervisor || !defined $prefix ){
		fail("Required params for upload_euca_image not defined");
		return -1;
	}
	
	$self->set_timeout(600);
	
	my @kernel = $self->sys("ls -m1 $dir/$hypervisor-kernel/vmlinuz* | xargs -n1 basename");
	my @ramdisk = $self->sys("ls -m1 $dir/$hypervisor-kernel/initrd* | xargs -n1 basename");
	my @image = $self->sys("ls -m1 $dir/*.img | xargs -n1 basename");
    chomp(@kernel);
	chomp(@ramdisk);
	chomp(@image);
	#$self->sys("mkdir bundle");	
	$self->sys("$self->{TOOLKIT}bundle-image -i $dir/$hypervisor-kernel/$kernel[0] -d bundle --kernel true");
	$self->sys("$self->{TOOLKIT}upload-bundle -b $prefix-kernel-bucket -m bundle/$kernel[0].manifest.xml");
	my @eki_result = $self->sys("$self->{TOOLKIT}register $prefix-kernel-bucket/$kernel[0].manifest.xml");
	if( $eki_result[0] !~ /eki/){
		fail("Kernel not uploaded properly: $eki_result[0]");
		return -1;
	}

	$self->sys("$self->{TOOLKIT}bundle-image -i $dir/$hypervisor-kernel/$ramdisk[0] -d bundle --ramdisk true");
	$self->sys("$self->{TOOLKIT}upload-bundle -b $prefix-ramdisk-bucket -m bundle/$ramdisk[0].manifest.xml");
	my @eri_result = $self->sys("$self->{TOOLKIT}register $prefix-ramdisk-bucket/$ramdisk[0].manifest.xml");
	if($eri_result[0] !~ /eri/){
		fail("Ramdisk not uploaded properly");
		return -1;
	}
	
	my @eki = split(/\s/, $eki_result[0]);
	my @eri = split(/\s/, $eri_result[0]);
	my @img = split(/\//, $dir); 
	my $dircount = @img - 1;
	my $imagename = $img[ $dircount ];
	$self->sys("$self->{TOOLKIT}bundle-image -i $dir/$imagename.img --ramdisk $eri[1] -d bundle --kernel $eki[1]");
	$self->sys("$self->{TOOLKIT}upload-bundle -b $prefix-image-bucket -m bundle/$imagename.img.manifest.xml");
	my @emi_result = $self->sys("$self->{TOOLKIT}register $prefix-image-bucket/$imagename.img.manifest.xml");
	my @emi = split(/\s/, $emi_result[0]);
	$self->set_timeout(120);
	$self->sys("rm -rf bundle");	
	if($emi_result[0] !~ /emi/){
		fail("Image not uploaded properly");
		return -1;
	}
	
	return ($emi[1], $eri[1], $eki[1]);
	
}

sub deregister_image{
	my $self = shift;
	my $image = shift;
	test_name("Deregistering image $image");
	
	## Execute deregister command
	my @dereg1 = $self->sys("$self->{TOOLKIT}deregister $image");
	
	##If there was no output fail
	if ( @dereg1 < 1){
		fail("Deregister image the first time did not return any output");
		return -1;
	}else{
		## Was the image in the output
		if( $dereg1[0] =~ /$image/){
			my @desc1 = $self->sys("$self->{TOOLKIT}describe-images | grep $image");
			## Is the image still in the desc-images output
			if( @desc1 < 1){
				fail( "Image $image removed from describe images on first deregister");
				return -1;
			}else{
				## Need to deregister a second time to remove it if its in deregistered 
				if( $desc1[0] =~ /deregistered/ ){
					my @dereg2 = $self->sys("$self->{TOOLKIT}deregister $image");
					
					if( @dereg2 < 1 ){
						fail("Deregister image the second time did not return any output");
						return -1;
					}else{
						my @desc2 = $self->sys("$self->{TOOLKIT}describe-images | grep $image");
						if( @desc2 < 1){
							pass("Successfully deregistered image $image");
							my @image_info = split(/\s/,$desc1[0]);
							my @bucket = split(/\//, $image_info[2]);
							$self->delete_bundle("$bucket[0]");
							return $image;
						}else{
							fail("Image still in store\n@desc2");
							return -1;
						}
					}
					
				}else{
					fail("Image not in deregistered state\n$desc1[0]\n");
					return -1;
				}
				
			}
			
		}
	}
	return -1;
	
}

sub delete_bundle{
	my $self = shift;
	my $bundle = shift;
	my @deletebundle = $self->sys("$self->{TOOLKIT}delete-bundle --clear -b $bundle");
	if( @deletebundle <1){
		pass("Delete bundle seems to have succeeded");
		return 0;
	}else{
		fail("Output returned from delete-bundle\n@deletebundle");
		return -1;
	}
	
}

sub run_instance{
	my $self = shift;
	my $keypair = shift;
	my $group = shift;
	my $OPTS = shift;
	my $time= time();
	if( !defined $keypair){
		$keypair = $self->add_keypair("keypair-" . $time);
	}
	if ( !defined $group){
		$group = "group-" . $time;
	    $self->add_group($group );
		
	}
	my $address = $self->allocate_address();
	my $emi = $self->get_emi();
#	my $keypath =$self->add_keypair($keypair);
#	$self->add_group($group);
	test_name("Sending run instance command");
	my $base_command = "$self->{TOOLKIT}run-instances -g $group -k $keypair  $emi";
	my @flags = ();
	
	my @output =  $self->sys($base_command);
	if ( @output < 1){
		fail("Initial attempt at running instance returned nothing");
		return -1;
	}
	
	### There was output to the run instance command, check if it includes INSTANCE  
	my @instance = grep(/INSTANCE/, @output);
	if( @instance < 1){
		fail("Initial attempt at running instance returned:\n@output");
		return -1;
	}
	
	### Check for state pending of the INSTANCE right after the run instance command  
	if ($instance[0] =~ /pending/){
		my @instance = split(' ', $instance[0]);
		my $instance_id = $instance[1];
		
		### Waiting for 20s 
		test_name("Sleeping 20 seconds for instance to get its IP");
		sleep 20;
		my ($emi, $ip, $state) = $self->get_instance_info($instance_id);
		## If emi- is found then we can assume we have the rest of the info as well
		if ( $emi !~ /emi-/){
			fail ("Could not find the instance in the describe instances pool after issuing run and waiting 20s");
			return -1;
		}
		## If we have the info make sure that the Public IP is not stuck on 0.0.0.0
		if( $ip =~ /0\.0\.0\.0/){
			fail ("Instance did not get an address within 20s");
			return -1;
		}
		
		pass("Instance $instance_id started with emi $emi at $instance[9] with IP= $ip");
		
		
		### Poll the instance every 20s for 300s until it leaves the pending state
		my $period = 20;
		my $count = 0;
		while ( ($state eq "pending") && ($count < 15) ){
			test_name("Polling every 20s until instance in running state");
			sleep $period;
			
			($emi, $ip, $state) = $self->get_instance_info($instance_id);
			if( $emi !~ /emi/){
				fail("Could not find the instance in the describe instances pool");
				return -1;
			}
			$count++;
		}
		
		### If the instance is not running after 300s there was an error
		if( $state ne "running"){
			fail("Instance went from pending to $state after 300s");
			return ($instance_id, $emi, $ip, $state, $keypair);
		}else{
			### Returns ($instance_id,  $emi, $ip, $state);
			pass("Instance is now in $state state after " . ( $count * $period ) . " seconds");
			return ($instance_id,  $emi, $ip, $state, $keypair);
		}
		
		
	}
	else{
		fail("Instance not in pending state after run");
		return -1;
	}
	
}


sub terminate_instance{
	my $self = shift;
	my $instance_id = shift;	
	my @output = $self->sys("$self->{TOOLKIT}terminate-instances $instance_id");
	if( @output < 1 ){
		fail("Terminate instance command failed");
		return -1;
	}
	if($output[0] =~ /$instance_id/){
		sleep 30; 
		my @describe_instances = $self->sys("$self->{TOOLKIT}describe-instances | grep $instance_id");
		if(@describe_instances < 1){
			fail("After terminating instance it is no longer found in the describe instances output");
			return -1;
		}
		my @instance = split(' ', $describe_instances[0]);
		if($instance[5] =~ /terminated/){
			pass("Successfully terminated instance $instance_id");
			return $instance_id;
		}
		else{
			fail("Unable to terminate $instance_id, stuck in $instance[5] state");
			return -1;
		}
	}else{
		fail("Unable to terminate $instance_id");
		return -1;
	}
	
}


sub get_instance_info{
	my $self = shift;
	my $instance_id = shift;
	my @running = $self->sys("$self->{TOOLKIT}describe-instances $instance_id | grep INSTANCE");
		if( @running < 1){
			fail("Did not find the instance in the describe instances pool");
			return -1;
		}else{
			my @info = split(' ', $running[0]);
			### Returns ($emi, $ip, $state);
			return ($info[2], $info[3], $info[5], $info[6]);
		}
}

sub teardown_instance{
	my $self= shift;
	my $instance_id = shift;
	my $ip = shift;
	$self->terminate_instance($instance_id);
	sleep 30;
	$self->release_address($ip);
	
}

sub reboot_instance{
	my $self = shift;
	my $instance_id = shift;
	my ($emi, $ip, $state, $keypair) = $self->get_instance_info($instance_id);
	my @uptime_old = $self->sys("ssh root\@$ip -i $keypair.priv \"cat /proc/uptime | awk \'{print \$1}\'\"");
	my @output = $self->sys("$self->{TOOLKIT}reboot-instances $instance_id");
	sleep 80;
	my @uptime_new = $self->sys("ssh root\@$ip -i $keypair.priv \"cat /proc/uptime | awk \'{print \$1}\'\"");
	if( $uptime_old[0] > $uptime_new[0]) {
		pass("Instance rebooted. Old uptime: $uptime_old[0]  New uptime:  $uptime_new[0]");
		return $instance_id;
	}else{
		fail("Uptime is greater than before reboot. Must not have rebooted instance properly");
		return -1;
	}
}

sub create_volume{
	my $self = shift;
	my $zone = shift;
	my $opts = shift;
	
	my $vol_timeout = 30;
	
	if( !defined $zone){
		fail("Required parameter zone not provided to function create_volume");
		return -1;
	}
	if( !defined $opts->{"size"} && !defined $opts->{"snapshot"}){
		fail("Required parameter size or snapshot not provided to function create_volume");
		return -1;
	}
	my $cmd = "$self->{TOOLKIT}create-volume -z $zone";
	
	if( defined $opts->{"size"}){
		$cmd .= " -s " . $opts->{"size"};
	}elsif( defined $opts->{"snapshot"}){
		$cmd .= " --snapshot " . $opts->{"snapshot"};
	}
	
	
	my @vol_create = $self->sys($cmd);
	
	
	my @vol_id = split(/\s+/, $vol_create[0]);
	
	if ( $vol_create[0] !~ /$vol_id[1].*creating.*/ ){
		fail("After running volume-create output does not show $vol_id[1] as creating");
		return -1;
	}
	else{
		sleep $vol_timeout;
		if ( ! $self->found("$self->{TOOLKIT}describe-volumes", qr/$vol_id[1].*$zone.*available.*/) ){
			fail("Unable to create volume");
			return -1;
		}
		else{
			pass("Volume $vol_id[1] created properly");
			return $vol_id[1];
		}	
	}
	
	
}

sub delete_volume{
	my $self = shift;
	my $volume = shift;
	
	if( !$self->found("$self->{TOOLKIT}delete-volume $volume", qr/^VOLUME\s+$volume/) ){
		fail("Failed to delete volume");
		return -1;
	}
	sleep 5;
	if( $self->found("$self->{TOOLKIT}describe-volumes", qr/^VOLUME\s+$volume.*available/ ) ){
		fail("After delete volume still available");
		return -1;
	}else{
		return $volume;
	}
	
}

sub attach_volume{
	my $self = shift;
	my $volume = shift;
	my $instance = shift;
	my $device = shift;
	
	
	if( !$self->found("$self->{TOOLKIT}attach-volume $volume -i $instance -d $device", qr/^VOLUME\s+$volume/ ) ){
		fail("Attachment failed");
		return -1;
	}elsif( !$self->found("$self->{TOOLKIT}describe-volumes",qr/^VOLUME\s+$volume.*in-use/ )  ){
		fail("Attachment not appearing in describe volumes as in use");
		return -1;
	}else{
		return $volume;
	}
}

sub detach_volume{
	my $self = shift;
	my $volume = shift;
	
	if( !$self->found("$self->{TOOLKIT}detach-volume $volume", qr/^VOLUME\s$volume/)){
		fail("Detach command did not return correct status");
		return -1;
	}
	sleep 5;
	if( !$self->found("$self->{TOOLKIT}describe-volumes",qr/^VOLUME\s+$volume.*available/ ) ){
		fail("Volume still attached after 5 seconds");
		return -1;
	}
	
	return $volume;
}

sub create_snapshot{
		my $self = shift;
        my $volume = shift;
        my @create_output = $self->sys("euca-create-snapshot $volume");
        my $poll_interval = 20;
        my $poll_count = 15;
        ### Check that there was output from the create command
        if( @create_output < 1){
        	fail("Create snapshot returned without output");
        	return -1;
        }{
        	### If there was output check that it shows the SNAPSHOT as pending and the current percentage is increasing
        	if( $create_output[0] =~ /^SNAPSHOT.*pending/){
        		my @snapshot_info = split(/ /,$create_output[0] );
        		my $snap_id = $snapshot_info[1];
        		pass("Snapshot $snap_id being created and in pending state");
        		my $old_percentage = 0;
        		my $current_state = "pending";
        		
        		
        		while( ($poll_count > 0) && ($current_state ne "completed")){
        			sleep $poll_interval;
        			my @snapshot_poll = $self->sys("euca-describe-snapshots | grep $snap_id");
        			if( @snapshot_poll < 1){
        				fail("Did not find $snap_id in describe-snapshots");
        				return -1;
        			}
        			my @snapshot_info = split(/ /,$snapshot_poll[0] );
        			my @new_percentage = split (/%/,$snapshot_info[5]);
        			if( $new_percentage[0] > $old_percentage){
        				test_name("Snapshot went from $old_percentage to $new_percentage[0]");
        				$old_percentage = $new_percentage[0];
        				$current_state = $snapshot_info[3] ;
        				$poll_count--;
        				
        			}else{
        				fail("Snapshot at same percentage after $poll_interval");
        				return -1;
        			}
        			
        		}
        		
        		if( $current_state eq "completed"){
        			pass("Successfully created snapshot $snap_id");
        			return $snap_id;
        		}else{
        			fail("Snapshot creation failed");
        			return -1;
        		}
        		
        	
        	}else{
        		fail("Snapshot not in pending state after create");
        		return -1;
        	}
        }
}

sub delete_snapshot {
	my $self = shift;
    my $snap = shift;

    if ($snap !~ /snap-/ ) {
		fail("ERROR: invalid snapshot ID '$snap' for delete_snapshot");
		return -1;
    }

    my $cmd = "$self->{TOOLKIT}delete-snapshot $snap";
    my @del_out = $self->sys($cmd);
    if (@del_out < 1){
    	fail("Delete snapshot returned no output");
    	return -1;
    }elsif ( $del_out[0] !~ "snap-") {
	 	fail("Deleting snapshot did not return snap-id\n");
	 	return -1;
    }else{
    	
    }
   
    
    return $snap;
}

#### EUARE COMMANDS ########################


sub euare_create_account{
	my $self = shift;
	my $new_account = shift;
	
	$self->sys("euare-accountcreate -a $new_account");
	if (!$self->found("euare-accountlist", qr/^$new_account/)) {
  		fail("fail to add account $new_account");
  		return -1;
	}
	return $new_account;
}

sub euare_delete_account{
	my $self = shift;
	my $deleted_account = shift;
	$self->sys("euare-accountdel -a $deleted_account -r");
	if ($self->found("euare-accountlist", qr/^$deleted_account/)) {
  		fail("failed to delete account $deleted_account");
  		return -1
	}
	return $deleted_account;
}

sub euare_create_user{
	my $self = shift;
	my $new_user = shift;
	my $account = shift;
	my $user_path = shift;
	
	$self->sys("euare-usercreate -u $new_user -p $user_path");
	if (!$self->found("euare-userlistbypath", qr/arn:aws:iam::$account:user$user_path\/$new_user/)) {
  		fail("could not create new user $new_user\@$account");
  		return -1;
	}
	return $new_user;
}

sub euare_change_username{
	my $self = shift;
	my $old_user_name = shift;
	my $new_user_name = shift;
	my $account = shift;
	my $path = shift;
	
	$self->sys("euare-usermod -u $old_user_name --new-user-name=$new_user_name");
	if (!$self->found("euare-userlistbypath", qr/arn:aws:iam::$account:user$path\/$new_user_name/)) {
  		fail("failed to change user name");
  		return -1;
	}
	return $new_user_name;
}

sub euare_clean_accounts {
	my $self = shift;
    my @accounts = $self->sys("euare-accountlist");
    for my $account (@accounts) {
    	chomp($account);
    	my @pair = split(qr/\s+/, $account);
    	if ($pair[0] ne "eucalyptus") {
      		$self->sys("euare-accountdel -a $pair[0] -r");
    	}
  	}
  @accounts = $self->sys("euare-accountlist");

  if (@accounts > 1 || !($accounts[0] =~ /^eucalyptus/)) {
    fail("failed to clean up accounts");
    return -1;
  }
  return 0;

}

sub euare_add_userinfo{ 
	my $self = shift;
	my $user = shift;
	my $key = shift;
	my $value = shift;
	
	test_name("Update $user info: $key=$value");
	$self->sys("euare-userupdateinfo -u $user -k $key -i $value");
	if (!$self->found("euare-usergetinfo -u $user", qr/$key\s+$value/)) {
  		fail("failed to add user info");
	}
}


sub euare_create_loginprofile{
	my $self = shift;
	my $user = shift;
	my $password = shift;
	$self->sys("euare-useraddloginprofile -u $user -p $password");
	if (!$self->found("euare-usergetloginprofile -u $user", qr/^$user$/)) {
 		 fail("failed to add password");
 		 return -1;
	}
	return 0;
}

sub euare_delete_loginprofile{
	my $self = shift;
	my $user = shift;
	
	$self->sys("euare-userdelloginprofile -u $user");
	if ($self->found("euare-usergetloginprofile -u $user", qr/^$user$/)) {
  		fail("there should be no password");
  		return -1;
	}
	return 0;

}

sub euare_add_userkey{
	my $self= shift;
	my $user = shift;
	

	$self->sys("euare-useraddkey -u $user");
	my @res = $self->sys("euare-userlistkeys -u $user");
	if (@res < 1) {
  		fail("failed to add access key");
  		return -1;
	}
	
	my $key = $res[0];
	chomp($key);

	### ENSURE KEY IS FOUND
	if (!$self->found("euare-userlistkeys -u $user", qr/$key/)) {
	  fail("failed to get user key");
	  return -1;
	}
	test_name("Check that key is active");
	if (!$self->found("euare-userlistkeys -u $user", qr/Active/)) {
	  fail("wrong user key status");
	  return -1;
	}
	return $key;
	
}

sub euare_deactivate_key{
	my $self= shift;
	my $user = shift;
	my $key = shift;
	test_name("Deactivate the key");
	$self->sys("euare-usermodkey -u $user -k $key -s Inactive");
	if (!$self->found("euare-userlistkeys -u $user", qr/Inactive/)) {
 	 fail("wrong user key status");
 	 return -1;
	}
	return 0;	
}

sub euare_delete_key{
	my $self = shift;
	my $user = shift;
	my $key = shift;
	
	test_name("Delete the key");
	$self->sys("euare-userdelkey -u $user -k $key");
	if ($self->found("euare-userlistkeys -u $user", qr/$key/)) {
 		fail("failed to delete user key");
 		return -1
	}
	return 0;
}


sub euare_create_cert{
	my $self = shift;
	my $user = shift;
	
	
	test_name("create user certificate");
	$self->sys("euare-usercreatecert -u $user");
	my @res = $self->sys("euare-userlistcerts -u $user");
	if (@res < 1) {
  		fail("failed to create certificate");
  		return -1;
	}
	my $cert = $res[0];
	chomp($cert);
	test_name("Check that certificate exists");
	if (!$self->found("euare-userlistcerts -u $user", qr/$cert/)) {
  		fail("failed to get user cert");
  		return -1;
	}

	test_name("Check that cert is active");
	if (!$self->found("euare-userlistcerts -u $user", qr/Active/)) {
  		fail("wrong user cert status");
  		return -1;
	}
	return $cert;
}

sub euare_deactviate_cert{
	my $self = shift;
	my $user = shift;
	my $cert = shift;
	
	test_name("Deactivate Cert");
	$self->sys("euare-usermodcert -u $user -c $cert -s Inactive");
	if (!$self->found("euare-userlistcerts -u $user", qr/Inactive/)) {
  		fail("wrong user cert status");
  		return -1;
	}
	return 0;
}


sub euare_delete_cert{
	my $self = shift;
	my $user = shift;
	my $cert = shift;
	test_name("Delete cert");
	$self->sys("euare-userdelcert -u $user -c $cert");
	if ($self->found("euare-userlistcerts -u $user", qr/$cert/)) {
  		fail("failed to delete user cert");
  		return -1;
	}
}

sub euare_add_certfromfile{
	my $self = shift;
	my $user = shift;
	my $filename = shift;
	
	test_name("Add user certificate from file");
	my @res = $self->sys("euare-useraddcert -u $user -f $filename");
	my $cert = $res[0];
	chomp($cert);

	sleep(5);

	test_name("Check that certificate exists");
	if (!$self->found("euare-userlistcerts -u $user", qr/$cert/)) {
	  fail("failed to get user cert");
	  return -1;
	}

	test_name("Check that cert is active");
	if (!$self->found("euare-userlistcerts -u $user", qr/Active/)) {
	  fail("wrong user cert status");
	  return -1;
	}
	return $cert;
}

sub get_currentaccount{
	my $self = shift;
	my @cred_path = split(/-/, $self->{CREDPATH});
	return $cred_path[1];
}

sub euare_create_group{
	my $self = shift;
	my $group = shift;
	my $path = shift;
	my $account = $self->get_currentaccount();
	$self->sys("euare-groupcreate -g $group -p $path");
	if (!$self->found("euare-grouplistbypath", qr/arn:aws:iam::$account:group$path\/$group/)) {
	  fail("could not create new group $group");
	  return -1;
	}
	return $group;
}

sub euare_parse_arn{
	my $self = shift;
	my $type = shift;
	my $name = shift;
	
		my @group = $self->sys("euare-" . $type . "listbypath | grep $name");
		if( @group < 1){
			fail("Unable to locate desired $type $name");
			return -1;
		}
		my @arn = split(/:/, $group[0]);
		my $pathindx =  @arn - 1;
		my @path = split(/\//, $arn[ $pathindx ]);
		my $fullpath = "/";
		for( my $counter = 1; $counter < @path -1 ; $counter++){
			$fullpath .= $path[$counter] . "/";
		}
		
		return  $fullpath;
	
}

sub euare_modattr{
	my $self = shift;
	my $type = shift;
	my $name = shift;
	my $opts = shift;
	my $account = $self->get_currentaccount();
	if( !defined $type){
		fail("Required parameter type not provided to function euare_modattr");
		return -1;
	}
	if( !defined $opts->{"path"} && !defined $opts->{"newname"}){
		fail("Required parameter path or name not provided to function euare_modattr");
		return -1;
	}
	my $path = $self->euare_parse_arn($type, $name);
	my $cmd = "euare-" . $type . "mod";
	if($type eq "group"){
		$cmd .= " -g $name";
	}else{
		$cmd .= " -u $name";
	}
	
	if( defined $opts->{"path"}){
		$cmd .= " -n " . $opts->{"path"};
		$path = $opts->{"path"};
	}elsif( defined $opts->{"newname"}){
		$cmd .= " --new-group-name " . $opts->{"newname"};
		$name = $opts->{"newname"};
	}
	
	$self->sys($cmd);
	if (!$self->found("euare-" . $type . "listbypath", qr/arn:aws:iam::$account:$type$path$name/)) {
  		fail("failed to change group path");
	}
}



1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

EucaTest - Perl extension for Testing Eucalyptus on the QA infrastructure 

=head1 SYNOPSIS

  use EucaTest;
  This module is intended to act on an Eucalyptus installation using euca2ools that are installed either locally or on a remote host.
  Both basic building blocks (ie running an arbitrary command on the remote machine) and high level test constructs (ie runnning an instance) are presented to allow test designers the highest level of flexibilty. 
  

=head1 DESCRIPTION



=head2 EXPORT

None by default.


=head1 HISTORY

=over 8

=item 0.01

Original version; created by h2xs 1.23 with options

  -ACXn
	EucaTest is now working under the Eucalyptus QA system. 

=back



=head1 SEE ALSO

www.eucalyptus.com

=head1 AUTHOR

Victor Iglesias, E<lt>vic.iglesias@eucalyptus.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Victor Iglesias

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
