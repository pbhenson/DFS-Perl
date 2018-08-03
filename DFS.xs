/*
 * DFS-Perl version 0.15
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dce/dce_error.h>
#include <dce/rpc.h>
#include <dce/secsts.h>
#include <dce/sec_login.h>
#include <dcedfs/common_data.h>
#include <dcedfs/compat.h>
#include <dcedfs/flserver.h>
#include <dcedfs/flclient.h>
#include <dcedfs/ftserver.h>
#include <dcedfs/ftserver_proc.h>
#include <dcedfs/ftserver_data.h>
#include <dcedfs/ioctl.h>
#include <dcedfs/volume.h>
#include <dcedfs/vol_errs.h>


#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif


typedef afsFid *DCE__DFS__fid;

typedef struct flserver_obj {
  rpc_binding_handle_t flserver_h[3];
  int flserver_h_count;

  /* VL_GenerateSites */
  unsigned32 site_start, site_nextstart;
  bulkSites site_info;
  unsigned32 site_count;
  unsigned32 site_index;

  /* VL_ListByAttributes */
  VldbListByAttributes attributes;
  bulkentries entry_info;
  unsigned32 entry_start, entry_nextstart;
  unsigned32 entry_index;

} flserver_obj;

typedef flserver_obj *DCE__DFS__flserver;


typedef struct ftserver_obj {
  rpc_binding_handle_t ftserver_h;
  afsNetAddr addr;

  /* FTSERVER_ListAggregates */ 
  ftserver_iterator aggr_start, aggr_nextstart;
  ftserver_aggrEntries aggr_entries;
  unsigned32 aggr_index;

} ftserver_obj;

typedef ftserver_obj *DCE__DFS__ftserver;


typedef struct aggregate_obj {
  rpc_binding_handle_t ftserver_h;
  afsNetAddr addr;

  unsigned32 id;
  ftserver_aggrInfo aggr_info;
} aggregate_obj;

typedef aggregate_obj *DCE__DFS__aggregate;


typedef struct fileset_obj {
  rpc_binding_handle_t ftserver_h;
  afsNetAddr addr;

  vldbentry entry;
  ftserver_status status;
} fileset_obj;

typedef fileset_obj *DCE__DFS__fileset;
  

static error_status_t bind_flservers(char *cell_fs, flserver_obj *flserver)
{
  unsigned32 import_status, group_status, rpc_status;
  rpc_ns_handle_t import_context;
  rpc_ns_handle_t group_context;
  unsigned_char_t *name, *string_binding, *protseq, *network_addr;
  uuid_t obj_uuid;
  unsigned_char_t *string_uuid;
  rpc_binding_handle_t temp_h;

  rpc_ns_entry_object_inq_begin(rpc_c_ns_syntax_default, cell_fs, &import_context, &import_status);

  if (import_status)
    return import_status;

  rpc_ns_entry_object_inq_next(import_context, &obj_uuid, &import_status);

  if (import_status)
    return import_status;

  rpc_ns_entry_object_inq_done(&import_context, &import_status);

  uuid_to_string(&obj_uuid, &string_uuid, &import_status);

  if (import_status)
    return import_status;

  
  rpc_ns_group_mbr_inq_begin(rpc_c_ns_syntax_default, cell_fs, rpc_c_ns_syntax_default,
                             &group_context, &group_status);

  if (group_status)
    return group_status;
  
  while ((!group_status) &&  (flserver->flserver_h_count < 3))
    {
      rpc_ns_group_mbr_inq_next(group_context, &name, &group_status);

      if (!group_status)
        {
          rpc_ns_binding_import_begin(rpc_c_ns_syntax_default, name, NULL,
                                      NULL, &import_context, &import_status);

          if (import_status)
            {
              rpc_ns_binding_import_done(&import_context, &import_status);
              continue;
            }

          rpc_ns_binding_import_next(import_context, &temp_h, &import_status);

          if (import_status)
            {
              rpc_ns_binding_import_done(&import_context, &import_status);
              continue;
            }

          rpc_binding_to_string_binding(temp_h, &string_binding, &import_status);
          rpc_binding_free(&temp_h, &rpc_status);
          
          if (import_status)
            {
              rpc_ns_binding_import_done(&import_context, &import_status);
              continue;
            }
          
          rpc_string_binding_parse(string_binding, NULL, &protseq, &network_addr,
                                   NULL, NULL, &import_status);
          rpc_string_free(&string_binding, &rpc_status);

          if (import_status)
            {
              rpc_ns_binding_import_done(&import_context, &import_status);
              continue;
            }
          
          rpc_string_binding_compose(string_uuid,
                                     protseq, network_addr, NULL, NULL,
                                     &string_binding, &import_status);
          rpc_string_free(&protseq, &rpc_status);
          rpc_string_free(&network_addr, &rpc_status);

          if (import_status)
            {
              rpc_ns_binding_import_done(&import_context, &import_status);
              continue;
            }
          
          rpc_binding_from_string_binding(string_binding,
                                          &flserver->flserver_h[flserver->flserver_h_count],
                                          &import_status);
          rpc_string_free(&string_binding, &rpc_status);

          if (!import_status)
            flserver->flserver_h_count++;
          
          rpc_ns_binding_import_done(&import_context, &import_status);
        }
    }
  rpc_ns_group_mbr_inq_done(&group_context, &group_status);
  rpc_string_free(&string_uuid, &import_status);

  return 0;
}

static error_status_t init_ftserver_h(rpc_binding_handle_t *ftserver_h, afsNetAddr *addr)
{
  unsigned_char_t *string_binding, *s_name;
  sec_login_handle_t login_context;
  error_status_t status, status2;

  rpc_string_binding_compose(NULL, "ncadg_ip_udp",
			     inet_ntoa(((struct sockaddr_in *)(addr))->sin_addr),
                             NULL, NULL, &string_binding, &status);

  if (status) return status;

  rpc_binding_from_string_binding(string_binding, ftserver_h, &status);
  rpc_string_free(&string_binding, &status2);

  if (status) return status;

  sec_login_get_current_context(&login_context,	&status);
  if (!status)
    {
      rpc_ep_resolve_binding(*ftserver_h, FTSERVER_v4_0_c_ifspec, &status);
      if (!status) {
	rpc_mgmt_inq_server_princ_name(*ftserver_h, rpc_c_authn_default, &s_name, &status);
	if (!status) {
	  rpc_binding_set_auth_info(*ftserver_h, s_name, rpc_c_protect_level_default,
				    rpc_c_authn_default, login_context,
				    rpc_c_authz_dce, &status);
	  rpc_string_free(&s_name, &status);
	}
      }
    }

  return 0;
}

static error_status_t init_ftserver(DCE__DFS__ftserver ftserver)
{
  unsigned_char_t *string_binding, *s_name;
  sec_login_handle_t login_context;
  error_status_t status;

  if (status = init_ftserver_h(&ftserver->ftserver_h, &ftserver->addr))
    return status;

  ftserver->aggr_start.index = ftserver->aggr_nextstart.index = ftserver->aggr_index = 0;
  ftserver->aggr_entries.ftserver_aggrList_len = 0;

  return 0;
}

static int
not_here(s)
char *s;
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant(name, arg)
char *name;
int arg;
{
    errno = 0;
    switch (*name) {
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}


MODULE = DCE::DFS		PACKAGE = DCE::DFS


double
constant(name,arg)
	char *		name
	int		arg


void
cellname(path)
     char *path
     CODE:
       struct afs_ioctl ioctl_buf;
       char cellname[300];

       ioctl_buf.in_size = 0;
       ioctl_buf.out_size = sizeof(cellname);
       ioctl_buf.out = cellname;

       if (!pioctl(path, VIOC_FILE_CELL_NAME, &ioctl_buf, 1))
         ST(0) = sv_2mortal(newSVpv(cellname, strlen(cellname)));
       else
         ST(0) = &sv_undef;


void
fid(path)
    char *path
    CODE:
      struct afs_ioctl ioctl_buf;
      DCE__DFS__fid fid;

      ST(0) = &sv_undef;

      if (fid = (DCE__DFS__fid)malloc(sizeof(struct afsFid))) {
        ioctl_buf.in_size = 0;
        ioctl_buf.out_size = sizeof(struct afsFid);
        ioctl_buf.out = (caddr_t) fid;

        if (!pioctl(path, VIOCGETFID, &ioctl_buf, 1)) {
          SV *sv = sv_newmortal();
          sv_setref_pv(sv, "DCE::DFS::fid", (void*)fid);
          ST(0) = sv;
        }
        else {
          free(fid);
        }
      }

void
flserver(cell_fs = "/.:/fs")
     char *cell_fs
     PPCODE:
     {
       SV *sv;
       DCE__DFS__flserver flserver;
       error_status_t status;

       if (!(flserver = (DCE__DFS__flserver)malloc(sizeof(flserver_obj))))
	 {
	   sv = &sv_undef;
	   XPUSHs(sv);
	   sv = sv_2mortal(newSViv(sec_s_no_memory));
	   XPUSHs(sv);
	 }
       else
	 {
	   flserver->flserver_h_count = 0;
	   flserver->site_start = flserver->site_count = flserver->site_index = 0;
	   
	   flserver->attributes.Mask = 0;
	   flserver->entry_info.bulkentries_len = flserver->entry_start = flserver->entry_nextstart = 0;
	   flserver->entry_index = 0;

	   status = bind_flservers(cell_fs, flserver);
	   if ( (status) || (flserver->flserver_h_count == 0) )
	     {
	       free(flserver);
	       sv = &sv_undef;
	       XPUSHs(sv);
	       sv = sv_2mortal(newSViv((status) ? (status) : (-1)));
	       XPUSHs(sv);
	     }
	   else
	     {
	       sv = sv_newmortal();
	       sv_setref_pv(sv,"DCE::DFS::flserver", (void *)flserver);
	       XPUSHs(sv);
	       sv = sv_2mortal(newSViv(0));
	       XPUSHs(sv);
	     }
	 }
     }


MODULE = DCE::DFS		PACKAGE = DCE::DFS::fid

void
DESTROY(fid)
     DCE::DFS::fid fid
     CODE:
       free((void *)fid);


MODULE = DCE::DFS		PACKAGE = DCE::DFS::flserver

void
DESTROY(flserver)
     DCE::DFS::flserver flserver
     CODE:
     {
       int index;
       unsigned32 status;
       
       for (index = 0; index < flserver->flserver_h_count; index++)
	 rpc_binding_free(&flserver->flserver_h[index], &status);
       
       free((void *)flserver);
     }

void
ftserver(flserver)
     DCE::DFS::flserver flserver
     PPCODE:
     {
       DCE__DFS__ftserver ftserver;
       error_status_t status = 0;
       SV *sv;
       
       if (GIMME == G_ARRAY)
	 {
	   while(!status)
	     {
	       for( ; flserver->site_index < flserver->site_count; flserver->site_index++)
		 {
		   if (ftserver = (DCE__DFS__ftserver)malloc(sizeof(ftserver_obj)))
		     {
		       ftserver->addr = flserver->site_info.Sites[flserver->site_index].Addr[0];
		       if (!init_ftserver(ftserver))
			   {
			     sv = sv_newmortal();
			     sv_setref_pv(sv,"DCE::DFS::ftserver", (void *)ftserver);
			     XPUSHs(sv);
 			   }
		       else
			 {
			   free(ftserver);
			 }
		     }
		 }
	       status = VL_GenerateSites(flserver->flserver_h[0],
					 flserver->site_start, &flserver->site_nextstart,
					 &flserver->site_info, &flserver->site_count);
	       flserver->site_start = flserver->site_nextstart;
	       flserver->site_index = 0;
	     }
	   flserver->site_start = flserver->site_count = flserver->site_index = 0;
	 }
       else
	 {
	   sv = &sv_undef;
	   if (flserver->site_index >= flserver->site_count)
	     {
	       status = VL_GenerateSites(flserver->flserver_h[0],
					 flserver->site_start, &flserver->site_nextstart,
					 &flserver->site_info, &flserver->site_count);
	       flserver->site_start = flserver->site_nextstart;
	       flserver->site_index = 0;
	     }
	   if ((status) || (flserver->site_count == 0))
	     {
	       flserver->site_start = flserver->site_count = flserver->site_index = 0;
	     }
	   else
	     {
	       if (ftserver = (DCE__DFS__ftserver)malloc(sizeof(ftserver_obj)))
		 {
		   ftserver->addr = flserver->site_info.Sites[flserver->site_index].Addr[0];
		   if (!init_ftserver(ftserver))
		     {
		       sv = sv_newmortal();
		       sv_setref_pv(sv,"DCE::DFS::ftserver", (void *)ftserver);
		     }
		   else
		     {
		       free(ftserver);
		     }
		 }
	       flserver->site_index++;
	     }
	   XPUSHs(sv);
	 }
     }

void
fileset_mask_reset(flserver)
     DCE::DFS::flserver flserver
     CODE:
       flserver->attributes.Mask = 0;

void
fileset_mask_ftserver(flserver, ftserver)
     DCE::DFS::flserver flserver
     DCE::DFS::ftserver ftserver
     CODE:
     {
       flserver->attributes.site = ftserver->addr;
       flserver->attributes.Mask |= VLLIST_SITE;
     }

void
fileset_mask_aggregate(flserver, aggr)
     DCE::DFS::flserver flserver
     DCE::DFS::aggregate aggr
     CODE:
     {
       flserver->attributes.partition = aggr->id;
       flserver->attributes.Mask |= VLLIST_PARTITION;
     }

void
fileset(flserver)
     DCE::DFS::flserver flserver
     PPCODE:
     {
       DCE__DFS__fileset fileset;
       error_status_t status = 0;
       unsigned32 dummy, dummy2;
       SV *sv;

       if (GIMME == G_ARRAY)
	 {
	   while(!status)
	     {
	       for( ; flserver->entry_index < flserver->entry_info.bulkentries_len; flserver->entry_index++)
		 {
		   if (fileset = (DCE__DFS__fileset)malloc(sizeof(fileset_obj)))
		     {
		       fileset->addr = flserver->entry_info.bulkentries_val[flserver->entry_index].siteAddr[0];
		       fileset->entry = flserver->entry_info.bulkentries_val[flserver->entry_index];
		       if (!(status = init_ftserver_h(&fileset->ftserver_h, &fileset->addr)))
			 {
			   if (!(status = FTSERVER_GetOneVolStatus(fileset->ftserver_h,
								   &fileset->entry.VolIDs[0],
								   fileset->entry.sitePartition[0],
								   0, &fileset->status)))
			     {
			       sv = sv_newmortal();
			       sv_setref_pv(sv,"DCE::DFS::fileset", (void *)fileset);
			       XPUSHs(sv);
			     }
			   else
			     {
			       rpc_binding_free(&fileset->ftserver_h, &status);
			       free(fileset);
			     }
			 }
		       else
			 {
			   free(fileset);
			 }
		     }
		 }
	       status = VL_ListByAttributes(flserver->flserver_h[0], &flserver->attributes, flserver->entry_start,
					    &dummy, &flserver->entry_info, &flserver->entry_nextstart, &dummy2);

	       flserver->entry_start = flserver->entry_nextstart;
	       flserver->entry_index = 0;
	     }
	   flserver->entry_start = flserver->entry_info.bulkentries_len = flserver->entry_index = 0;
	 }
       else
	 {
	   sv = &sv_undef;
	   if (flserver->entry_index >= flserver->entry_info.bulkentries_len)
	     {
	       status = VL_ListByAttributes(flserver->flserver_h[0], &flserver->attributes, flserver->entry_start,
					    &dummy, &flserver->entry_info, &flserver->entry_nextstart, &dummy2);

	       flserver->entry_start = flserver->entry_nextstart;
	       flserver->entry_index = 0;
	     }
	   if ((status) || (flserver->entry_info.bulkentries_len == 0))
	     {
	       flserver->entry_start = flserver->entry_info.bulkentries_len = flserver->entry_index = 0;
	     }
	   else
	     {
	       if (fileset = (DCE__DFS__fileset)malloc(sizeof(fileset_obj)))
		 {
		   fileset->addr = flserver->entry_info.bulkentries_val[flserver->entry_index].siteAddr[0];
		   fileset->entry = flserver->entry_info.bulkentries_val[flserver->entry_index];
		   if (!(status = init_ftserver_h(&fileset->ftserver_h, &fileset->addr)))
		     {
		       if (!(status = FTSERVER_GetOneVolStatus(fileset->ftserver_h,
							       &fileset->entry.VolIDs[0],
							       fileset->entry.sitePartition[0],
							       0, &fileset->status)))
			 {
			   sv = sv_newmortal();
			   sv_setref_pv(sv,"DCE::DFS::fileset", (void *)fileset);
			 }
		       else
			 {
			   rpc_binding_free(&fileset->ftserver_h, &status);
			   free(fileset);
			 }
		     }
		   else
		     {
		       free(fileset);
		     }
		   flserver->entry_index++;
		 }
	     }
	   XPUSHs(sv);
	 }
     }

void
fileset_by_name(flserver, name)
     DCE::DFS::flserver flserver
     char *name
     PPCODE:
     {
       error_status_t status;
       DCE__DFS__fileset fileset;
       SV *sv = &sv_undef;

       if (fileset = (DCE__DFS__fileset)malloc(sizeof(fileset_obj)))
	 {
	   if (!(status = VL_GetEntryByName(flserver->flserver_h[0], name, &fileset->entry)))
	     {
	       fileset->addr = fileset->entry.siteAddr[0];
	       if (!(status = init_ftserver_h(&fileset->ftserver_h, &fileset->addr)))
		 {
		   if (!(status = FTSERVER_GetOneVolStatus(fileset->ftserver_h, &fileset->entry.VolIDs[0],
							   fileset->entry.sitePartition[0], 0, &fileset->status)))
		     {
		       sv = sv_newmortal();
		       sv_setref_pv(sv,"DCE::DFS::fileset", (void *)fileset);
		     }
		   else
		     {
		       rpc_binding_free(&fileset->ftserver_h, &status);
		       free(fileset);
		     }
		 }
	       else
		 {
		   free(fileset);
		 }
	     }
	   else
	     {
	       free(fileset);
	     }
	 }
			 
       XPUSHs(sv);
     }


void
fileset_by_id(flserver, fid)
     DCE::DFS::flserver flserver
     DCE::DFS::fid fid
     PPCODE:
     {
       error_status_t status;
       DCE__DFS__fileset fileset;
       SV *sv = &sv_undef;

       if (fileset = (DCE__DFS__fileset)malloc(sizeof(fileset_obj)))
	 {
	   if (!(status = VL_GetEntryByID(flserver->flserver_h[0], &fid->Volume, -1, &fileset->entry)))
	     {
	       fileset->addr = fileset->entry.siteAddr[0];
	       if (!(status = init_ftserver_h(&fileset->ftserver_h, &fileset->addr)))
		 {
		   if (!(status = FTSERVER_GetOneVolStatus(fileset->ftserver_h, &fileset->entry.VolIDs[0],
							   fileset->entry.sitePartition[0], 0, &fileset->status)))
		     {
		       sv = sv_newmortal();
		       sv_setref_pv(sv,"DCE::DFS::fileset", (void *)fileset);
		     }
		   else
		     {
		       rpc_binding_free(&fileset->ftserver_h, &status);
		       free(fileset);
		     }
		 }
	       else
		 {
		   free(fileset);
		 }
	     }
	   else
	     {
	       free(fileset);
	     }
	 }

       XPUSHs(sv);
     }


MODULE = DCE::DFS		PACKAGE = DCE::DFS::ftserver

void
DESTROY(ftserver)
     DCE::DFS::ftserver ftserver
     CODE:
     {
       unsigned32 status;

       rpc_binding_free(&ftserver->ftserver_h, &status);
       free((void *)ftserver);
     }

void
address(ftserver)
     DCE::DFS::ftserver ftserver
     CODE:
     {
       char *address = inet_ntoa(((struct sockaddr_in *)(&ftserver->addr))->sin_addr);

       if (address)
	 ST(0) = sv_2mortal(newSVpv(address, strlen(address)));
       else
	 ST(0) = &sv_undef;
     }

void
hostname(ftserver)
     DCE::DFS::ftserver ftserver
     CODE:
     {
       struct hostent *host = gethostbyaddr((const char *)&((struct sockaddr_in *)(&ftserver->addr))->sin_addr,
					    sizeof(((struct sockaddr_in *)(&ftserver->addr))->sin_addr),
					    AF_INET);
       char *retval;

       if (host)
	 retval = host->h_name;
       else
	 retval = inet_ntoa(((struct sockaddr_in *)(&ftserver->addr))->sin_addr);

       if (retval)
	 ST(0) = sv_2mortal(newSVpv(retval, strlen(retval)));
       else
	 ST(0) = &sv_undef;
     }


void
aggregate(ftserver)
     DCE::DFS::ftserver ftserver
     PPCODE:
     {
       DCE__DFS__aggregate aggr;
       error_status_t status;
       int more_entries = 1;
       SV *sv;
       
       if (GIMME == G_ARRAY)
	 {
	   while(more_entries)
	     {
	       for( ; ftserver->aggr_index < ftserver->aggr_entries.ftserver_aggrList_len; ftserver->aggr_index++)
		 {
		   if (aggr = (DCE__DFS__aggregate)malloc(sizeof(aggregate_obj)))
		     {
		       if (!FTSERVER_AggregateInfo(ftserver->ftserver_h,
						   ftserver->aggr_entries.ftserver_aggrEntries_val[ftserver->aggr_index].Id,
						   &aggr->aggr_info))
			 {
			   rpc_binding_copy(ftserver->ftserver_h, &aggr->ftserver_h, &status);
			   aggr->addr = ftserver->addr;
			   aggr->id = ftserver->aggr_entries.ftserver_aggrEntries_val[ftserver->aggr_index].Id;
			   sv = sv_newmortal();
			   sv_setref_pv(sv, "DCE::DFS::aggregate", (void *)aggr);
			   XPUSHs(sv);
			 }
		       else
			 {
			   free(aggr);
			 }
		     }
		 }
	       status = FTSERVER_ListAggregates(ftserver->ftserver_h, &ftserver->aggr_start,
						&ftserver->aggr_nextstart, &ftserver->aggr_entries);
	       
	       if (ftserver->aggr_start.index == ftserver->aggr_nextstart.index)
		 {
		   ftserver->aggr_start.index = ftserver->aggr_nextstart.index = ftserver->aggr_index = 0;
		   ftserver->aggr_entries.ftserver_aggrList_len = 0;
		   more_entries = 0;
		 }
	       else
		 {
		   ftserver->aggr_start.index = ftserver->aggr_nextstart.index;
		   ftserver->aggr_index = 0;
		 }
	     }
	 }
       else
	 {
	   sv = &sv_undef;
	   if (ftserver->aggr_index >= ftserver->aggr_entries.ftserver_aggrList_len)
	     {
	       status = FTSERVER_ListAggregates(ftserver->ftserver_h, &ftserver->aggr_start,
						&ftserver->aggr_nextstart, &ftserver->aggr_entries);

	       if (ftserver->aggr_start.index == ftserver->aggr_nextstart.index)
		 ftserver->aggr_start.index = ftserver->aggr_nextstart.index = 0;
	       else
		 ftserver->aggr_start = ftserver->aggr_nextstart;

	       ftserver->aggr_index = 0;
	     }
	   if (ftserver->aggr_entries.ftserver_aggrList_len > 0)
	     {
	       if (aggr = (DCE__DFS__aggregate)malloc(sizeof(aggregate_obj)))
		 {
		   if (!FTSERVER_AggregateInfo(ftserver->ftserver_h,
					       ftserver->aggr_entries.ftserver_aggrEntries_val[ftserver->aggr_index].Id,
					       &aggr->aggr_info))
		     {
		       rpc_binding_copy(ftserver->ftserver_h, &aggr->ftserver_h, &status);
		       aggr->addr = ftserver->addr;
		       aggr->id = ftserver->aggr_entries.ftserver_aggrEntries_val[ftserver->aggr_index].Id;
		       sv = sv_newmortal();
		       sv_setref_pv(sv, "DCE::DFS::aggregate", (void *)aggr);
		     }
		   else
		     {
		       free(aggr);
		     }
		 }
	       ftserver->aggr_index++;
	     }
	   XPUSHs(sv);
	 }
     }


MODULE = DCE::DFS		PACKAGE = DCE::DFS::aggregate

void
DESTROY(aggr)
     DCE::DFS::aggregate aggr
     CODE:
     {
       unsigned32 status;

       rpc_binding_free(&aggr->ftserver_h, &status);
       free((void *)aggr);
     }


void
name(aggr)
     DCE::DFS::aggregate aggr
     CODE:
       ST(0) = sv_2mortal(newSVpv(aggr->aggr_info.name, strlen(aggr->aggr_info.name)));

void
device(aggr)
     DCE::DFS::aggregate aggr
     CODE:
       ST(0) = sv_2mortal(newSVpv(aggr->aggr_info.devName, strlen(aggr->aggr_info.devName)));

int
id(aggr)
     DCE::DFS::aggregate aggr
     CODE:
       RETVAL = aggr->id;
     OUTPUT:
       RETVAL

int
type(aggr)
     DCE::DFS::aggregate aggr
     CODE:
       RETVAL = aggr->aggr_info.type;
     OUTPUT:
       RETVAL

int
size(aggr)
     DCE::DFS::aggregate aggr
     CODE:
       RETVAL = aggr->aggr_info.totalUsable;
     OUTPUT:
       RETVAL

int
free(aggr)
     DCE::DFS::aggregate aggr
     CODE:
       RETVAL = aggr->aggr_info.curFree;
     OUTPUT:
       RETVAL


MODULE = DCE::DFS		PACKAGE = DCE::DFS::fileset

void
DESTROY(fileset)
     DCE::DFS::fileset fileset
     CODE:
     {
       unsigned32 status;

       rpc_binding_free(&fileset->ftserver_h, &status);
       free((void *)fileset);
     }

void
name(fileset)
     DCE::DFS::fileset fileset
     CODE:
       ST(0) = sv_2mortal(newSVpv(fileset->entry.name, strlen(fileset->entry.name)));

int
quota(fileset)
     DCE::DFS::fileset fileset
     CODE:
     {
       afsHyper hyper;
       int quota;
       
       hset(hyper, fileset->status.vsd.visQuotaLimit);
       hrightshift(hyper, 10);
       hget32(quota, hyper);

       RETVAL = quota;
     }
     OUTPUT:
       RETVAL

int
used(fileset)
     DCE::DFS::fileset fileset
     CODE:
     {
       afsHyper hyper;
       int used;
       
       hset(hyper, fileset->status.vsd.visQuotaUsage);
       hrightshift(hyper, 10);
       hget32(used, hyper);

       RETVAL = used;
     }
     OUTPUT:
       RETVAL

int
set_quota(fileset, quota)
     DCE::DFS::fileset fileset
     int quota
     CODE:
     {
       struct ftserver_status ft_status;
       long trans_id;
       error_status_t status = 0;

       if (!(status = FTSERVER_CreateTrans(fileset->ftserver_h, &fileset->entry.VolIDs[0], fileset->entry.sitePartition[0],
					 FLAGS_ENCODE(FTSERVER_OP_SETSTATUS, VOLERR_TRANS_SETQUOTA),
					 &trans_id)))
	 {
	   hset32(ft_status.vsd.visQuotaLimit, quota);
	   hleftshift(ft_status.vsd.visQuotaLimit, 10);

	   if (status = FTSERVER_SetStatus(fileset->ftserver_h, trans_id, VOL_STAT_VISLIMIT, &ft_status, 0))
	     FTSERVER_AbortTrans(fileset->ftserver_h, trans_id);
	   else
	     FTSERVER_DeleteTrans(fileset->ftserver_h, trans_id);
	 }

       RETVAL = status;
     }
     OUTPUT:
       RETVAL

int
update(fileset)
     DCE::DFS::fileset fileset
     CODE:
     {
       RETVAL = FTSERVER_GetOneVolStatus(fileset->ftserver_h, &fileset->entry.VolIDs[0],
					 fileset->entry.sitePartition[0], 0, &fileset->status);
     }
     OUTPUT:
       RETVAL
