package EucaTest;

use 5.000003;
use strict;
use warnings;

use Cwd qw(abs_path);

use lib 'Net-OpenSSH-0.52/lib';


require Exporter;
require Net::OpenSSH;


our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use EucaTest ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';


sub new{
	my $ssh;
	my $class = shift;
	my $opts = shift;
	my $host = $opts->{'host'};
	my $keypath = $opts->{'keypath'};
	### IF we are going to a remote server to exec commands
	if( defined $host ){
		print "Creating an SSH connection to $host\n";
		## are we authenticating with keys or with password alone
		if( defined $keypath){
			$ssh =  Net::OpenSSH->new( $host, key_path => $keypath ,  master_opts => [-o => "StrictHostKeyChecking=no" ]  );
			$ssh->error and
   			fail( $ssh->error);
		}else{
			$ssh =  Net::OpenSSH->new($host);
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
	
	my $self  = { SSH => $ssh , CREDPATH => $credpath, TIMEOUT => $timeout, EUCALYPTUS => $eucadir,  VERIFYLEVEL=> $verify_level, TOOLKIT => $toolkit};
	bless $self;
	return $self;
}

sub fail {
  my($message) = @_;
  print("^^^^^^[TEST_REPORT] FAILED - $message^^^^^^\n");
  #exit(1);
}

# Print formatted success message
sub pass {
  my($message) = @_;
  print("^^^^^^[TEST_REPORT] PASSED - $message^^^^^^\n\n");
  return 0;
}

# Print test case name (ie a description of the following steps)
sub test_name {
  my($name) = @_;
  print("******[TEST_REPORT] ACTION - $name ******\n");
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
	$self->{CREDPATH} = $credpath;
	return 0;
}

sub sys {
  my $self = shift;
  my $cmd = shift;
  my $timeout = shift;
  my $original_cmd = $cmd;
  if( $self->{CREDPATH} ne ""){
		$cmd = ". " . $self->{CREDPATH} ."/eucarc && " . $cmd;
  }
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
    
	if( defined  $self->{SSH} ){
		
		 print("[REMOTE COMMAND] $original_cmd\n");
		 # 
	
		  @output =  $self->{SSH}->capture( $cmd);
 		  #$self->{SSH}->error and fail( "SSH ERROR: " . $self->{SSH}->error);
		 
	}else{
		print("[LOCAL COMMAND] $original_cmd\n");
		
		@output = `$cmd`;
	}
	alarm(0);
		
	};
	if ($@) {
		die unless $@ eq "alarm\n"; # propagate unexpected errors
		# timed out
		fail("Timeout occured after $systimeout seconds\n"); 
		return @output;
	}
	else {		# didn't
		print "OUTPUT:\n" . "@output\n";
		return @output;
    
	}
	
}

sub read_input_file{
	my $self = shift;
	my $filename = shift;
	my $is_memo = 0;
	my $memo = "";
	my %CLC;
	open( INPUT, "< $filename" ) || die $!;

	my $line;
	while( $line = <INPUT> ){
		chomp($line);
		if( $is_memo ){
			if( $line ne "END_MEMO" ){
				$memo .= $line . "\n";
			};
		};

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
				print "IP $qa_ip [Distro $qa_distro, Version $qa_distro_ver, ARCH $qa_arch] is built from $qa_source as Eucalyptus-$qa_roll\n";
				$CLC{'QA_DISTRO'} = $qa_distro;
				$CLC{'QA_DISTRO_VER'} = $qa_distro_ver;
				$CLC{'QA_ARCH'} = $qa_arch;
				$CLC{'QA_SOURCE'} = $qa_source;
				$CLC{'QA_ROLL'} = $qa_roll;
				$CLC{'QA_IP'} = $qa_ip;
			};
		}elsif( $line =~ /^MEMO/ ){
			$is_memo = 1;
		}elsif( $line =~ /^END_MEMO/ ){
			$is_memo = 0;
		};
	};	

	close(INPUT);

	$CLC{'QA_MEMO'} = $memo;

	return %CLC;
};

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
	my $ip = shift;
	my @add_group = $self->sys("$self->{TOOLKIT}add-group $groupname -d $groupname");
	if($add_group[0] =~ /GROUP/){
		pass("Added group $groupname successfully");
	}
	else{ 
		fail("Unable to add group $groupname");
		return -1;
	}
	
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
	return (@add_group, @auth_icmp, @auth_ssh);
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
		
	$self->sys("$self->{TOOLKIT}bundle-image -i $dir/$hypervisor-kernel/$kernel[0] --kernel true");
	$self->sys("$self->{TOOLKIT}upload-bundle -b $prefix-kernel-bucket -m /tmp/$kernel[0].manifest.xml");
	my @eki_result = $self->sys("$self->{TOOLKIT}register $prefix-kernel-bucket/$kernel[0].manifest.xml");
	if( $eki_result[0] !~ /eki/){
		fail("Kernel not uploaded properly: $eki_result[0]");
		return -1;
	}
		
	$self->sys("$self->{TOOLKIT}bundle-image -i $dir/$hypervisor-kernel/$ramdisk[0] --ramdisk true");
	$self->sys("$self->{TOOLKIT}upload-bundle -b $prefix-ramdisk-bucket -m /tmp/$ramdisk[0].manifest.xml");
	my @eri_result = $self->sys("$self->{TOOLKIT}register $prefix-ramdisk-bucket/$ramdisk[0].manifest.xml");
	if($eri_result[0] !~ /eri/){
		fail("Ramdisk not uploaded properly");
		return -1;
	}
	
	my @eki = split(/\s/, $eki_result[0]);
	my @eri = split(/\s/, $eri_result[0]);
	
	$self->sys("$self->{TOOLKIT}bundle-image -i $dir/$image[0] --ramdisk $eri[1] --kernel $eki[1]");
	$self->sys("$self->{TOOLKIT}upload-bundle -b $prefix-image-bucket -m /tmp/$image[0].manifest.xml");
	my @emi_result = $self->sys("$self->{TOOLKIT}register $prefix-image-bucket/$image[0].manifest.xml");
	my @emi = split(/\s/, $emi_result[0]);
	$self->set_timeout(120);
	if($emi_result[0] !~ /emi/){
		fail("Image not uploaded properly");
		return -1;
	}
	
	
	return ($emi[1], $eri[1], $eki[1]);
	
}

sub run_instance{
	my $self = shift;
	my $keypair = shift;
	my $group = shift;
	my $address = $self->allocate_address();
	my $emi = $self->get_emi();
#	my $keypath =$self->add_keypair($keypair);
#	$self->add_group($group);
	test_name("Sending run instance command");
	my @output =  $self->sys("$self->{TOOLKIT}run-instances -k $keypair -g $group $emi | grep INSTANCE");
	if ($output[0] =~ /pending/){
		my @instance = split(' ', $output[0]);
		my $instance_id = $instance[1];
		test_name("Sleeping 20 seconds then checking instance state");
		sleep 20;
		my ($emi, $ip, $state) = $self->get_instance_info($instance_id);
		
		pass("Instance $instance_id started with emi $emi at $instance[9] with IP= $ip");
		
		
		while ( $state eq "pending"){
			test_name("Polling every 20s until instance in running state");
			sleep 20;
			
			($emi, $ip, $state) = $self->get_instance_info($instance_id);
			if( $emi !~ /emi/){
				fail("Could not find the instance in the describe instances pool");
				return -1;
			}
		}
		
		if( $state ne "running"){
			fail("Instance went from pending to $state");
			return -1;
		}else{
			### Returns ($instance_id,  $emi, $ip);
			pass("Instance is now in $state state");
			return ($instance_id,  $emi, $ip);
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
			return ($info[2], $info[3], $info[5]);
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
	
	if ( $vol_id[3] !~ /creating/ ){
		fail("After running volume-create output does not show $vol_id[1] as creating");
		return -1;
	}
	else{
		sleep $vol_timeout;
		if ( ! $self->found("$self->{TOOLKIT}describe-volumes", qr/$vol_id[1]/) ){
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
	}elsif( $self->found("$self->{TOOLKIT}describe-volumes", qr/^VOLUME\s+$volume/ ) ){
		fail("After delete volume still exists");
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
	
	return 1;
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
