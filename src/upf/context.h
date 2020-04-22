/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef UPF_CONTEXT_H
#define UPF_CONTEXT_H

#include "upf-config.h"

#if HAVE_NET_IF_H
#include <net/if.h>
#endif

#include "ogs-gtp.h"
#include "ogs-diameter-gx.h"
#include "ogs-pfcp.h"
#include "ogs-app.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __upf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __upf_log_domain

typedef struct upf_context_s {
    uint32_t        gtpu_port;      /* Default: UPF GTP-U local port */

    ogs_list_t      gtpu_list;      /* UPF GTPU Server List */
    ogs_sock_t      *gtpu_sock;     /* UPF GTPU IPv4 Socket */
    ogs_sock_t      *gtpu_sock6;    /* UPF GTPU IPv6 Socket */
    ogs_list_t      gtpu_resource_list; /* UP IP Resource List */
    uint16_t        function_features; /* UP Function Features */

    ogs_queue_t     *queue;         /* Queue for processing UPF control */
    ogs_timer_mgr_t *timer_mgr;     /* Timer Manager */
    ogs_pollset_t   *pollset;       /* Poll Set for I/O Multiplexing */

#define MAX_NUM_OF_DNS              2
    const char      *dns[MAX_NUM_OF_DNS];
    const char      *dns6[MAX_NUM_OF_DNS];

#define MAX_NUM_OF_P_CSCF           16
    const char      *p_cscf[MAX_NUM_OF_P_CSCF];
    int             num_of_p_cscf;
    int             p_cscf_index;
    const char      *p_cscf6[MAX_NUM_OF_P_CSCF];
    int             num_of_p_cscf6;
    int             p_cscf6_index;

    ogs_list_t      sgw_s5c_list;   /* SGW GTPC Node List */
    ogs_list_t      sgw_s5u_list;   /* SGW GTPU Node List */
    ogs_list_t      ip_pool_list;

    ogs_hash_t      *sess_hash;     /* hash table (F-SEID) */
    ogs_hash_t      *bearer_hash;   /* hash table (UPF-N3-TEID) */
    ogs_hash_t      *ipv4_hash;     /* hash table (IPv4 Address) */
    ogs_hash_t      *ipv6_hash;     /* hash table (IPv6 Address) */
} upf_context_t;

typedef struct upf_sess_s {
    ogs_lnode_t     lnode;
    uint32_t        index;          /**< An index of this node */

    uint32_t        sgw_s5c_teid;   /* SGW-S5C-TEID is received from SGW */

    char            *gx_sid;        /* Gx Session ID */

    ogs_pfcp_sess_t pfcp;

    /* APN Configuration */
    ogs_pdn_t       pdn;
    ogs_pfcp_ue_ip_t *ipv4;
    ogs_pfcp_ue_ip_t *ipv6;

    /* User-Lication-Info */
    ogs_tai_t       tai;
    ogs_e_cgi_t     e_cgi;

    /* Stored GTP message */
    ogs_gtp_create_session_request_t *create_session_request;
    ogs_gtp_delete_session_request_t *delete_session_request;

    ogs_list_t      bearer_list;

    /* Related Context */
    ogs_gtp_node_t  *gnode;
} upf_sess_t;

typedef struct upf_bearer_s {
    ogs_lnode_t     lnode; /**< A node of list_t */
    uint32_t        index;

    uint32_t        upf_n3_teid;
    uint32_t        sgw_s5u_teid;

    char            *name;          /* PCC Rule Name */
    ogs_qos_t       qos;            /* QoS Infomration */

    /* Packet Filter Identifier Generator(1~15) */
    uint8_t         pf_identifier;
    /* Packet Filter List */
    ogs_list_t      pf_list;

    upf_sess_t      *sess;
    ogs_gtp_node_t  *gnode;
} upf_bearer_t;

typedef struct upf_rule_s {
    uint8_t proto;
ED5(uint8_t ipv4_local:1;,
    uint8_t ipv4_remote:1;,
    uint8_t ipv6_local:1;,
    uint8_t ipv6_remote:1;,
    uint8_t reserved:4;)
    struct {
        struct {
            uint32_t addr[4];
            uint32_t mask[4];
        } local;
        struct {
            uint32_t addr[4];
            uint32_t mask[4];
        } remote;
    } ip;
    struct {
        struct {
            uint16_t low;
            uint16_t high;
        } local;
        struct {
            uint16_t low;
            uint16_t high;
        } remote;
    } port;
} upf_rule_t;

typedef struct upf_pf_s {
    ogs_lnode_t     lnode;

ED3(uint8_t spare:2;,
    uint8_t direction:2;,
    uint8_t identifier:4;)
    upf_rule_t      rule;

    upf_bearer_t    *bearer;
} upf_pf_t;

void upf_context_init(void);
void upf_context_final(void);
upf_context_t *upf_self(void);

int upf_context_parse_config(void);

upf_sess_t *upf_sess_add_by_message(ogs_pfcp_message_t *message);

upf_sess_t *upf_sess_add(ogs_pfcp_f_seid_t *f_seid,
        const char *apn, uint8_t pdn_type, ogs_pfcp_ue_ip_addr_t *ue_ip);
int upf_sess_remove(upf_sess_t *sess);
void upf_sess_remove_all(void);
upf_sess_t *upf_sess_find(uint32_t index);
upf_sess_t *upf_sess_find_by_cp_seid(uint64_t seid);
upf_sess_t *upf_sess_find_by_up_seid(uint64_t seid);
upf_sess_t *upf_sess_find_by_ipv4(uint32_t addr);
upf_sess_t *upf_sess_find_by_ipv6(uint32_t *addr6);

upf_bearer_t *upf_bearer_add(upf_sess_t *sess);
int upf_bearer_remove(upf_bearer_t *bearer);
void upf_bearer_remove_all(upf_sess_t *sess);
upf_bearer_t *upf_bearer_find(uint32_t index);
upf_bearer_t *upf_bearer_find_by_upf_n3_teid(uint32_t upf_n3_teid);
upf_bearer_t *upf_bearer_find_by_name(upf_sess_t *sess, char *name);
upf_bearer_t *upf_bearer_find_by_qci_arp(upf_sess_t *sess, 
                                uint8_t qci,
                                uint8_t priority_level,
                                uint8_t pre_emption_capability,
                                uint8_t pre_emption_vulnerability);
upf_bearer_t *upf_default_bearer_in_sess(upf_sess_t *sess);
upf_bearer_t *upf_bearer_first(upf_sess_t *sess);
upf_bearer_t *upf_bearer_next(upf_bearer_t *bearer);

upf_pf_t *upf_pf_add(upf_bearer_t *bearer, uint32_t precedence);
int upf_pf_remove(upf_pf_t *pf);
void upf_pf_remove_all(upf_bearer_t *bearer);
upf_pf_t *upf_pf_find_by_id(upf_bearer_t *upf_bearer, uint8_t id);
upf_pf_t *upf_pf_first(upf_bearer_t *bearer);
upf_pf_t *upf_pf_next(upf_pf_t *pf);

void stats_add_session(void);
void stats_remove_session(void);

#ifdef __cplusplus
}
#endif

#endif /* UPF_CONTEXT_H */
