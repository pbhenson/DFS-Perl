#!/usr/local/bin/perl
#
# Paul Henson <henson@acm.org>
#
# Copyright (c) 1997 Paul Henson -- see COPYRIGHT file for details
#

use DCE::DFS;

my $flserver;
my $ftserver;
my $aggr;
my $fileset;
my $status;

my $cell_fts;
my $cell_ft;
my $cell_ag;
my $cell_ft_alloc;
my $cell_ft_used;
my $cell_ag_size;
my $cell_ag_used;

($flserver, $status) = DCE::DFS::flserver();

if ($status) {
    print "Error creating flserver object: $status \n\n";
    exit 1;
}

my $cellname = DCE::DFS::cellname("/:/");

print "DFS usage report for " . $cellname . "\n";
print "---------------------";
for (my $i = 0; $i < length($cellname); $i++) { print "-"; }
print "\n\n";

while ($ftserver = $flserver->ftserver) {
    my $serv_ft;
    my $serv_ag;
    my $serv_ft_alloc;
    my $serv_ft_used;
    my $serv_ag_size;
    my $serv_ag_used;

    print "  Fileserver " . $ftserver->hostname . " (" . $ftserver->address . ")\n\n";

    $cell_fts++;

    $flserver->fileset_mask_reset;
    $flserver->fileset_mask_ftserver($ftserver);
    
    while ($aggr = $ftserver->aggregate) {
	my $aggr_ft;
	my $aggr_ft_alloc;
	my $aggr_ft_used;
	

	printf("     Aggregate %s (id %d, device %s, type %d, size %s)\n\n", $aggr->name, $aggr->id,
	                                                                    $aggr->device, $aggr->type,
                                                                            fmt_size($aggr->size));

	$flserver->fileset_mask_aggregate($aggr);

	while ($fileset = $flserver->fileset) {
	    printf("       %-30s %10s / %-10s (%0.2f%%)\n", $fileset->name, fmt_size($fileset->used),
		                                            fmt_size($fileset->quota),
		                                            ($fileset->used/$fileset->quota)*100);

	    $aggr_ft++;
	    $aggr_ft_alloc+=$fileset->quota;
	    $aggr_ft_used+=$fileset->used;
	}
	
	print "\n";
	print "       Aggregate total:     $aggr_ft filesets\n";
        printf("                            %s used / %s allocated (", fmt_size($aggr_ft_used), fmt_size($aggr_ft_alloc));
	printf("%0.2f%%)\n", ($aggr_ft_used/$aggr_ft_alloc)*100);
	print "                            ";
	print (($aggr_ft_alloc > $aggr->size) ? fmt_size(($aggr_ft_alloc - $aggr->size)) . " overallocated " :
	                                        fmt_size(($aggr->size - $aggr_ft_alloc)) . " unallocated ");
	print "on this aggregate\n\n";

	$cell_ft+=$aggr_ft;
	$cell_ag++;
	$cell_ft_alloc+=$aggr_ft_alloc;
	$cell_ft_used+=$aggr_ft_used;
	$cell_ag_size+=$aggr->size;
	$cell_ag_used+=($aggr->size-$aggr->free);

	$serv_ft+=$aggr_ft;
	$serv_ag++;
	$serv_ft_alloc+=$aggr_ft_alloc;
	$serv_ft_used+=$aggr_ft_used;
	$serv_ag_size+=$aggr->size;
	$serv_ag_used+=($aggr->size-$aggr->free);
    }

    print "    Fileserver total:     $serv_ag aggregates\n";
    print "                          $serv_ft filesets\n";
    printf("                          %s used / %s allocated (", fmt_size($serv_ft_used), fmt_size($serv_ft_alloc));
    printf("%0.2f%%)\n", ($serv_ft_used/$serv_ft_alloc)*100);
    print "                          ";
    print (($serv_ft_alloc > $serv_ag_size) ? fmt_size(($serv_ft_alloc - $serv_ag_size)) . " overallocated " :
	                                      fmt_size(($serv_ag_size - $serv_ft_alloc)) . " unallocated ");
    print "on this fileserver\n\n";
}

print "  Cell total:     $cell_fts fileservers\n";
print "                  $cell_ag aggregates\n";
print "                  $cell_ft filesets\n";
printf("                  %s used / %s allocated (", fmt_size($cell_ft_used), fmt_size($cell_ft_alloc));
printf("%0.2f%%)\n", ($cell_ft_used/$cell_ft_alloc)*100);
print "                  ";
print (($cell_ft_alloc > $cell_ag_size) ? fmt_size(($cell_ft_alloc - $cell_ag_size)) . " overallocated " :
	                                  fmt_size(($cell_ag_size - $cell_ft_alloc)) . " unallocated ");
print "in this cell\n\n";

exit;
	

sub fmt_size {
    my ($size) = @_;
    my $unit, $div;

    if ($size > 1048576) {
	$unit = "G";
	$div = 1048576;
    }
    elsif ($size > 1024) {
	$unit = "M";
	$div = 1024;
    }
    else {
	$unit = "K";
	$div = 1;
    }

    return (sprintf("%0.2f", $size/$div) . $unit);
}
    
