#ifndef _IDSA_SCHEMES_H_
#define _IDSA_SCHEMES_H_

/****************************************************************************
 * Copyright 2002, 2003 Marc Welz
 *
 * .ldm-1 by Marcus Ranum and Paul Robertson
 * .err-1, ssm-1, am-1, fnl-1, rq-1 by Marc Welz
 * 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/****************************************************************************
 * This file contains a number of schemes/schemas/namespaces/models/MIBs 
 * which can be used to emit events with an agreed upon meaning. 
 *
 * each field part of a defined scheme starts with a ".", followed by a 
 * short name, a "-" and an integer version
 */


/****************************************************************************
 * The common logfile format: 
 * See also http://www.w3.org/pub/WWW/Daemon/User/Config/Logging.html
 */

#define idsa_s_clf(p)  ".clf-1." p

/* Remote hostname (or IP number if DNS hostname is not available, or if DNSLookup is Off */
#define IDSA_CLF_REMOTEHOST  idsa_s_clf("remotehost")

/* The remote logname of the user. */
#define IDSA_CLF_RFC931      idsa_s_clf("rfc931")

/* The username as which the user has authenticated himself */
#define IDSA_CLF_AUTHUSER    idsa_s_clf("authuser")

/* Date and time of the request */
#define IDSA_CLF_DATE        idsa_s_clf("date")

/* The request line exactly as it came from the client */
#define IDSA_CLF_REQUEST     idsa_s_clf("request")

/* The HTTP status code returned to the client */
#define IDSA_CLF_STATUS      idsa_s_clf("status")

/* The content-length of the document transferred */
#define IDSA_CLF_BYTES       idsa_s_clf("bytes")


/****************************************************************************
 * The logging data map by Ranum and Robertson 
 * See http://www.ranum.com/logging/logging-data-map.html
 */

#define idsa_s_ldm(p)  ".ldm-1." p

#define IDSA_LDM_NDATE     idsa_s_ldm("n-date")
#define IDSA_LDM_SOURCEID  idsa_s_ldm("source-id")
#define IDSA_LDM_TRANSID   idsa_s_ldm("trans-id")
#define IDSA_LDM_PRIO      idsa_s_ldm("prio")
#define IDSA_LDM_REFS      idsa_s_ldm("refs")
#define IDSA_LDM_GEOLOC    idsa_s_ldm("geoloc")
#define IDSA_LDM_GROUP     idsa_s_ldm("group")
#define IDSA_LDM_RAWMSG    idsa_s_ldm("rawmsg")
#define IDSA_LDM_DESCRIPT  idsa_s_ldm("descript")
#define IDSA_LDM_OPERATION idsa_s_ldm("operation")
#define IDSA_LDM_PROTO     idsa_s_ldm("proto")
#define IDSA_LDM_ALERTMSG  idsa_s_ldm("alertmsg")
#define IDSA_LDM_ERRMSG    idsa_s_ldm("errmsg")
#define IDSA_LDM_SRCPID    idsa_s_ldm("srcpid")
#define IDSA_LDM_SRCIDENT  idsa_s_ldm("srcident")
#define IDSA_LDM_SRCUSER   idsa_s_ldm("srcuser")
#define IDSA_LDM_TARGUSER  idsa_s_ldm("targuser")
#define IDSA_LDM_SRCDEV    idsa_s_ldm("srcdev")
#define IDSA_LDM_TARGDEV   idsa_s_ldm("targdev")
#define IDSA_LDM_SRCCRED   idsa_s_ldm("srccred")
#define IDSA_LDM_TARGCRED  idsa_s_ldm("targcred")
#define IDSA_LDM_SRCPATH   idsa_s_ldm("srcpath")
#define IDSA_LDM_TARGPATH  idsa_s_ldm("targpath")


/****************************************************************************
 * a simple access control model. Subject, object and action are required
 */

#define idsa_s_am(p)  ".am-1." p

#define IDSA_AM_SUBJECT   idsa_s_am("subject")
#define IDSA_AM_OBJECT    idsa_s_am("object")
#define IDSA_AM_ACTION    idsa_s_am("action")

/* Plain read - transfers information to the subject */
#define IDSA_AM_AREAD     "action-read"

/* Plain write - transfers information to the object */
#define IDSA_AM_AWRITE    "action-write"

/* Subject generates an object not previously available */
#define IDSA_AM_ACREATE   "action-create"

/* Subject renders an object permanently inaccessible */
#define IDSA_AM_ADESTROY  "action-destroy"

/* Subject gains sufficient control over object so that subsequent 
 * actions performed by object could have been performed at the
 * request of this subject. Used to measure insecurity flow.
 * Appropriate for invoking nonsetuid executables, changing uid, 
 * remote logins
 */
#define IDSA_AM_AFLOW     "action-flow"

/* Subject requests a trusted object to perform an action. 
 * Appropriate for setuid execution, protocol commands
 */
#define IDSA_AM_AREQUEST  "action-request"

/* Fallback if none of the above actions are appropriate */
#define IDSA_AM_AOTHER    "action-other"

/* Specialised extensions */

#define IDSA_AM_CLEARANCE       idsa_s_am("clearance")
#define IDSA_AM_CLASSIFICATION  idsa_s_am("classification")
#define IDSA_AM_DOMAIN          idsa_s_am("domain")
#define IDSA_AM_TYPE            idsa_s_am("type")
#define IDSA_AM_ROLE            idsa_s_am("role")


/****************************************************************************
 * A simple error schema. Four major error types, those:
 *       Made by the user of the application (above)
 *       Internal to the application         (inside)
 *         anticipated, but not handled        (unimplemented functions)
 *         unexpected flaws                    (assert violations, should not happen)
 *       Made by a peer of the system        (adjacent)
 *         includes file format errors if at the same level
 *       Occurring in the host runtime       (below)
 *
 *       ES_USAGE
 *     +--------------------------+
 *     | ES_UNHANDLED/ES_INTERNAL |  <-> ES_PROTOCOL
 *     +--------------------------+
 *       ES_SYSTEM
 */

#define idsa_s_es(p)      ".es-1." p

#define IDSA_ES            idsa_s_es("error")

#define IDSA_ES_USAGE     "error-usage"	/* failure at user interface */
#define IDSA_ES_SYSTEM    "error-system"	/* failure at infrastructure */
#define IDSA_ES_PROTOCOL  "error-protocol"	/* failure at peer */
#define IDSA_ES_UNHANDLED "error-unhandled"	/* known unhandled condition */
#define IDSA_ES_INTERNAL  "error-internal"	/* worrying internal failure */
#define IDSA_ES_OTHER     "error-other"	/* other, hard to classify, error */

/* elaborate on error-system  */

#define IDSA_ES_SYS_ERRNO  idsa_s_es("errno")	/* see also /usr/include/errno.h */
#define IDSA_ES_SYS_EXIT   idsa_s_es("exit")	/* see also /usr/include/sysexists.h */

/* extra protocol errors */

#define IDSA_ES_PRO_HTTP   idsa_s_es("http")	/* see also RFC2068 */

/* could also include protocol error codes */


/****************************************************************************
 * A simple service model: state graph of an application, can be used to
 * monitor if a system is up or down, and its work rate/load/number of 
 * units of work in flight and error rate.
 *
 * constraints: service-start first event
 *              service-{fail,stop} last events
 *              work-start first work event
 *              work-{fail,stop} last work events
 *              between service-pause and work-start a service-continue is needed
 */

#define idsa_s_ssm(p)      ".ssm-1." p

#define IDSA_SSM            idsa_s_ssm("state")

#define IDSA_SSM_SSTART    "service-start"	/* service ready to do work */
#define IDSA_SSM_SPAUSE    "service-pause"	/* service suspended */
#define IDSA_SSM_SCONTINUE "service-continue"	/* service continued */
#define IDSA_SSM_SCONFIG   "service-config"	/* service reconfigured */
#define IDSA_SSM_SSTOP     "service-stop"	/* service completed successfully */
#define IDSA_SSM_SFAIL     "service-fail"	/* service terminated abnormally */

#define IDSA_SSM_WSTART    "work-start"	/* started a unit of work */
#define IDSA_SSM_WSTOP     "work-stop"	/* completed a unit of work successfully */
#define IDSA_SSM_WFAIL     "work-fail"	/* could not complete a unit of work */


/****************************************************************************
 * Functionality hierarchy of tasks in an application. Essential tasks are
 * labelled 0, less important tasks with positive numbers. LEVEL is the
 * current operation, MAX the least essential. Used to manage creeping
 * featurism. The availability_risk mandatory field can also be used.
 */

#define idsa_s_fnl(p)      ".fnl-1." p

#define IDSA_FNL_LEVEL     idsa_s_fnl("level")
#define IDSA_FNL_MAX       idsa_s_fnl("max")

/* Ftp server example
 * .ssm-1.state="service-start" .fnl-1.max="3"
 * ...
 * cmd="USER" .fnl-1.level="0"
 * cmd="PASS" .fnl-1.level="0"
 * cmd="CWD"  .fnl-1.level="1"
 * cmd="LIST" .fnl-1.level="1"
 * cmd="RNTO" .fnl-1.level="2" 
 * cmd="SITE" .fnl-1.level="3"
 * cmd="QUIT" .fnl-1.level="0"
 */


/****************************************************************************
 * Describe the number of resources held, requested and available to an
 * application. To identify owners and resource names, .am-1 can 
 * be used. The resources should be reported as positive integers
 *
 * REQUESTED or RELEASED are required. It may not be possible 
 * to always report FREE and TOTAL, and sometimes even USED may be omitted
 */

#define idsa_s_rq(p)      ".rq-1." p

/* The additional resources to be requested */
#define IDSA_RQ_REQUEST   idsa_s_rq("request")

/* Alternatively the resources to be made available again */
#define IDSA_RQ_RELEASE   idsa_s_rq("release")

/* The number of elements already held by the entity */
#define IDSA_RQ_USED      idsa_s_rq("used")

/* The number of resources available in total */
#define IDSA_RQ_FREE      idsa_s_rq("free")

/* The total number of resources, available or used */
#define IDSA_RQ_TOTAL     idsa_s_rq("total")

/* The units in which the resources are measured */
#define IDSA_RQ_UNITS     idsa_s_rq("units")

/* The abstract resource type  */
#define IDSA_RQ_CLASS     idsa_s_rq("class")
#define IDSA_RQ_CTRAFFIC   "traffic"	/* bytes sent */
#define IDSA_RQ_CPROCESSOR "processor"	/* seconds of cpu time */
#define IDSA_RQ_CSTORAGE   "storage"	/* bytes of storage */

/* Disk blocks example
 * name="create-file" .rq-1.units="diskblocks" .rq-1.used="0" .rq-1.request="1" 
 * name="write-file"  .rq-1.units="diskblocks" .rq-1.used="1" .rq-1.request="4" 
 * name="delete-file" .rq-1.units="diskblocks" .rq-1.used="5" .rq-1.release="5" 
 */

#endif
