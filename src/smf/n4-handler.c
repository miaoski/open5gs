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

#include "context.h"
#include "timer.h"
#include "pfcp-path.h"
#include "gtp-path.h"
#include "s5c-build.h"
#include "ipfw.h"
#include "ipfw/ipfw2.h"
#include "n4-handler.h"

static void bearer_binding(smf_sess_t *sess);

static uint8_t gtp_cause_from_pfcp(uint8_t pfcp_cause)
{
    switch (pfcp_cause) {
    case OGS_PFCP_CAUSE_REQUEST_ACCEPTED:
        return OGS_GTP_CAUSE_REQUEST_ACCEPTED;
    case OGS_PFCP_CAUSE_REQUEST_REJECTED:
        return OGS_GTP_CAUSE_REQUEST_REJECTED_REASON_NOT_SPECIFIED;
    case OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND:
        return OGS_GTP_CAUSE_CONTEXT_NOT_FOUND;
    case OGS_PFCP_CAUSE_MANDATORY_IE_MISSING:
        return OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    case OGS_PFCP_CAUSE_CONDITIONAL_IE_MISSING:
        return OGS_GTP_CAUSE_CONDITIONAL_IE_MISSING;
    case OGS_PFCP_CAUSE_INVALID_LENGTH:
        return OGS_GTP_CAUSE_INVALID_LENGTH;
    case OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT:
        return OGS_GTP_CAUSE_MANDATORY_IE_INCORRECT;
    case OGS_PFCP_CAUSE_INVALID_FORWARDING_POLICY:
    case OGS_PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION:
        return OGS_GTP_CAUSE_INVALID_MESSAGE_FORMAT;
    case OGS_PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION:
        return OGS_GTP_CAUSE_REMOTE_PEER_NOT_RESPONDING;
    case OGS_PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE:
        return OGS_GTP_CAUSE_SEMANTIC_ERROR_IN_THE_TFT_OPERATION;
    case OGS_PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION:
        return OGS_GTP_CAUSE_GTP_C_ENTITY_CONGESTION;
    case OGS_PFCP_CAUSE_NO_RESOURCES_AVAILABLE:
        return OGS_GTP_CAUSE_NO_RESOURCES_AVAILABLE;
    case OGS_PFCP_CAUSE_SERVICE_NOT_SUPPORTED:
        return OGS_GTP_CAUSE_SERVICE_NOT_SUPPORTED;
    case OGS_PFCP_CAUSE_SYSTEM_FAILURE:
        return OGS_GTP_CAUSE_SYSTEM_FAILURE;
    default:
        return OGS_GTP_CAUSE_SYSTEM_FAILURE;
    }

    return OGS_GTP_CAUSE_SYSTEM_FAILURE;
}

void smf_n4_handle_association_setup_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_association_setup_request_t *req)
{
    int i;

    ogs_assert(xact);
    ogs_assert(node);
    ogs_assert(req);

    smf_pfcp_send_association_setup_response(
            xact, OGS_PFCP_CAUSE_REQUEST_ACCEPTED);

    ogs_pfcp_gtpu_resource_remove_all(&node->gtpu_resource_list);

    for (i = 0; i < OGS_MAX_NUM_OF_GTPU_RESOURCE; i++) {
        ogs_pfcp_tlv_user_plane_ip_resource_information_t *message =
            &req->user_plane_ip_resource_information[i];
        ogs_pfcp_user_plane_ip_resource_info_t info;

        if (message->presence == 0)
            break;

        ogs_pfcp_parse_user_plane_ip_resource_info(&info, message);
        ogs_pfcp_gtpu_resource_add(&node->gtpu_resource_list, &info);
    }
}

void smf_n4_handle_association_setup_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_association_setup_response_t *rsp)
{
    int i;

    ogs_assert(xact);
    ogs_pfcp_xact_commit(xact);

    ogs_assert(node);
    ogs_assert(rsp);

    ogs_pfcp_gtpu_resource_remove_all(&node->gtpu_resource_list);

    for (i = 0; i < OGS_MAX_NUM_OF_GTPU_RESOURCE; i++) {
        ogs_pfcp_tlv_user_plane_ip_resource_information_t *message =
            &rsp->user_plane_ip_resource_information[i];
        ogs_pfcp_user_plane_ip_resource_info_t info;

        if (message->presence == 0)
            break;

        ogs_pfcp_parse_user_plane_ip_resource_info(&info, message);
        ogs_pfcp_gtpu_resource_add(&node->gtpu_resource_list, &info);
    }
}

void smf_n4_handle_heartbeat_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_heartbeat_request_t *req)
{
    ogs_assert(xact);
    ogs_pfcp_send_heartbeat_response(xact);
}

void smf_n4_handle_heartbeat_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_heartbeat_response_t *rsp)
{
    ogs_assert(xact);
    ogs_pfcp_xact_commit(xact);

    ogs_timer_start(node->t_heartbeat,
            smf_timer_cfg(SMF_TIMER_HEARTBEAT)->duration);
}

void smf_n4_handle_session_establishment_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_establishment_response_t *rsp)
{
    uint8_t cause_value = 0;
    ogs_gtp_xact_t *gtp_xact = NULL;
    ogs_pfcp_f_seid_t *up_f_seid = NULL;

    ogs_assert(xact);
    ogs_assert(rsp);

    gtp_xact = xact->assoc_xact;
    ogs_assert(gtp_xact);

    ogs_pfcp_xact_commit(xact);

    cause_value = OGS_GTP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_warn("No Context");
        cause_value = OGS_GTP_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (rsp->up_f_seid.presence == 0) {
        ogs_error("No UP F-SEID");
        cause_value = OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (rsp->cause.presence) {
        if (rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_warn("Cause[%d] : No Accepted", rsp->cause.u8);
            cause_value = gtp_cause_from_pfcp(rsp->cause.u8);
        }
    } else {
        ogs_error("No Cause");
        cause_value = OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_GTP_CAUSE_REQUEST_ACCEPTED) {
        ogs_gtp_send_error_message(gtp_xact, sess ? sess->sgw_s5c_teid : 0,
                OGS_GTP_CREATE_SESSION_RESPONSE_TYPE, cause_value);
        return;
    }

    ogs_assert(sess);

    /* UP F-SEID */
    up_f_seid = rsp->up_f_seid.data;
    ogs_assert(up_f_seid);
    sess->pfcp.remote_n4_seid = be64toh(up_f_seid->seid);

    smf_gtp_send_create_session_response(sess, gtp_xact);

    bearer_binding(sess);
}

void smf_n4_handle_session_deletion_response(
        smf_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_deletion_response_t *rsp)
{
    uint8_t cause_value = 0;
    ogs_gtp_xact_t *gtp_xact = NULL;

    ogs_assert(xact);
    ogs_assert(rsp);

    gtp_xact = xact->assoc_xact;
    ogs_assert(gtp_xact);

    ogs_pfcp_xact_commit(xact);

    cause_value = OGS_GTP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_warn("No Context");
        cause_value = OGS_GTP_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (rsp->cause.presence) {
        if (rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_warn("Cause[%d] : No Accepted", rsp->cause.u8);
            cause_value = gtp_cause_from_pfcp(rsp->cause.u8);
        }
    } else {
        ogs_error("No Cause");
        cause_value = OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_GTP_CAUSE_REQUEST_ACCEPTED) {
        ogs_gtp_send_error_message(gtp_xact, sess ? sess->sgw_s5c_teid : 0,
                OGS_GTP_DELETE_SESSION_RESPONSE_TYPE, cause_value);
        return;
    }

    ogs_assert(sess);

    smf_gtp_send_delete_session_response(sess, gtp_xact);

    smf_sess_remove(sess);
}

static void encode_traffic_flow_template(
        ogs_gtp_tft_t *tft, smf_bearer_t *bearer)
{
    int i, j, len;
    smf_pf_t *pf = NULL;

    ogs_assert(tft);
    ogs_assert(bearer);

    memset(tft, 0, sizeof(*tft));
    tft->code = OGS_GTP_TFT_CODE_CREATE_NEW_TFT;

    i = 0;
    pf = smf_pf_first(bearer);
    while (pf) {
        tft->pf[i].direction = pf->direction;
        tft->pf[i].identifier = pf->identifier - 1;
        tft->pf[i].precedence = i+1;

        j = 0, len = 0;
        if (pf->rule.proto) {
            tft->pf[i].component[j].type =
                GTP_PACKET_FILTER_PROTOCOL_IDENTIFIER_NEXT_HEADER_TYPE;
            tft->pf[i].component[j].proto = pf->rule.proto;
            j++; len += 2;
        }

        if (pf->rule.ipv4_local) {
            tft->pf[i].component[j].type =
                GTP_PACKET_FILTER_IPV4_LOCAL_ADDRESS_TYPE;
            tft->pf[i].component[j].ipv4.addr = pf->rule.ip.local.addr[0];
            tft->pf[i].component[j].ipv4.mask = pf->rule.ip.local.mask[0];
            j++; len += 9;
        }

        if (pf->rule.ipv4_remote) {
            tft->pf[i].component[j].type =
                GTP_PACKET_FILTER_IPV4_REMOTE_ADDRESS_TYPE;
            tft->pf[i].component[j].ipv4.addr = pf->rule.ip.remote.addr[0];
            tft->pf[i].component[j].ipv4.mask = pf->rule.ip.remote.mask[0];
            j++; len += 9;
        }

        if (pf->rule.ipv6_local) {
            tft->pf[i].component[j].type =
                GTP_PACKET_FILTER_IPV6_LOCAL_ADDRESS_PREFIX_LENGTH_TYPE;
            memcpy(tft->pf[i].component[j].ipv6.addr, pf->rule.ip.local.addr,
                    sizeof pf->rule.ip.local.addr);
            tft->pf[i].component[j].ipv6.prefixlen =
                contigmask((uint8_t *)pf->rule.ip.local.mask, 128);
            j++; len += 18;
        }

        if (pf->rule.ipv6_remote) {
            tft->pf[i].component[j].type =
                GTP_PACKET_FILTER_IPV6_REMOTE_ADDRESS_PREFIX_LENGTH_TYPE;
            memcpy(tft->pf[i].component[j].ipv6.addr, pf->rule.ip.remote.addr,
                    sizeof pf->rule.ip.remote.addr);
            tft->pf[i].component[j].ipv6.prefixlen =
                contigmask((uint8_t *)pf->rule.ip.remote.mask, 128);
            j++; len += 18;
        }

        if (pf->rule.port.local.low) {
            if (pf->rule.port.local.low == pf->rule.port.local.high)
            {
                tft->pf[i].component[j].type =
                    GTP_PACKET_FILTER_SINGLE_LOCAL_PORT_TYPE;
                tft->pf[i].component[j].port.low = pf->rule.port.local.low;
                j++; len += 3;
            } else {
                tft->pf[i].component[j].type =
                    GTP_PACKET_FILTER_LOCAL_PORT_RANGE_TYPE;
                tft->pf[i].component[j].port.low = pf->rule.port.local.low;
                tft->pf[i].component[j].port.high = pf->rule.port.local.high;
                j++; len += 5;
            }
        }

        if (pf->rule.port.remote.low) {
            if (pf->rule.port.remote.low == pf->rule.port.remote.high) {
                tft->pf[i].component[j].type =
                    GTP_PACKET_FILTER_SINGLE_REMOTE_PORT_TYPE;
                tft->pf[i].component[j].port.low = pf->rule.port.remote.low;
                j++; len += 3;
            } else {
                tft->pf[i].component[j].type =
                    GTP_PACKET_FILTER_REMOTE_PORT_RANGE_TYPE;
                tft->pf[i].component[j].port.low = pf->rule.port.remote.low;
                tft->pf[i].component[j].port.high = pf->rule.port.remote.high;
                j++; len += 5;
            }
        }

        tft->pf[i].num_of_component = j;
        tft->pf[i].length = len;
        i++;

        pf = smf_pf_next(pf);
    }
    tft->num_of_packet_filter = i;
}

static void timeout(ogs_gtp_xact_t *xact, void *data)
{
    smf_sess_t *sess = data;
    uint8_t type = 0;

    ogs_assert(sess);

    type = xact->seq[0].type;

    ogs_debug("GTP Timeout : SGW_S5C_TEID[0x%x] SMF_N4_TEID[0x%x] "
            "Message-Type[%d]", sess->sgw_s5c_teid, sess->smf_n4_teid, type);
}

static void bearer_binding(smf_sess_t *sess)
{
    int rv;
    int i, j;

    ogs_assert(sess);

    for (i = 0; i < sess->num_of_pcc_rule; i++) {
        ogs_gtp_xact_t *xact = NULL;
        ogs_gtp_header_t h;
        ogs_pkbuf_t *pkbuf = NULL;
        smf_bearer_t *bearer = NULL;

        ogs_pcc_rule_t *pcc_rule = &sess->pcc_rule[i];
        int bearer_created = 0;
        int qos_presence = 0;
        ogs_gtp_tft_t tft;

        ogs_assert(pcc_rule);
        if (pcc_rule->name == NULL) {
            ogs_error("No PCC Rule Name");
            continue;
        }

        if (pcc_rule->type == OGS_PCC_RULE_TYPE_INSTALL) {
            bearer = smf_bearer_find_by_qci_arp(sess, 
                        pcc_rule->qos.qci,
                        pcc_rule->qos.arp.priority_level,
                        pcc_rule->qos.arp.pre_emption_capability,
                        pcc_rule->qos.arp.pre_emption_vulnerability);
            if (!bearer) {
                if (pcc_rule->num_of_flow == 0) {
                    /* TFT is mandatory in
                     * activate dedicated EPS bearer context request */
                    ogs_error("No flow in PCC Rule");
                    continue;
                }

                bearer = smf_bearer_add(sess);
                ogs_assert(bearer);

                bearer->name = ogs_strdup(pcc_rule->name);
                ogs_assert(bearer->name);

                memcpy(&bearer->qos, &pcc_rule->qos, sizeof(ogs_qos_t));

                bearer_created = 1;
            } else {
                ogs_assert(strcmp(bearer->name, pcc_rule->name) == 0);

                if (pcc_rule->num_of_flow) {
                    /* We'll use always 'Create new TFT'.
                     * Therefore, all previous flows are removed
                     * and replaced by the new flow */
                    smf_pf_remove_all(bearer);
                }

                if ((pcc_rule->qos.mbr.downlink &&
                    bearer->qos.mbr.downlink != pcc_rule->qos.mbr.downlink) ||
                    (pcc_rule->qos.mbr.uplink &&
                     bearer->qos.mbr.uplink != pcc_rule->qos.mbr.uplink) ||
                    (pcc_rule->qos.gbr.downlink &&
                    bearer->qos.gbr.downlink != pcc_rule->qos.gbr.downlink) ||
                    (pcc_rule->qos.gbr.uplink &&
                    bearer->qos.gbr.uplink != pcc_rule->qos.gbr.uplink)) {
                    /* Update QoS parameter */
                    memcpy(&bearer->qos, &pcc_rule->qos, sizeof(ogs_qos_t));

                    /* Update Bearer Request encodes updated QoS parameter */
                    qos_presence = 1;
                }

                if (pcc_rule->num_of_flow == 0 && qos_presence == 0) {
                    ogs_warn("No need to send 'Update Bearer Request'");
                    ogs_warn("  - Both QoS and TFT are same as before");
                    continue;
                }
            }

            for (j = 0; j < pcc_rule->num_of_flow; j++) {
                ogs_flow_t *flow = &pcc_rule->flow[j];
                smf_rule_t rule;
                smf_pf_t *pf = NULL;

                ogs_expect_or_return(flow);
                ogs_expect_or_return(flow->description);

                rv = smf_compile_packet_filter(&rule, flow->description);
                ogs_expect_or_return(rv == OGS_OK);

                pf = smf_pf_add(bearer, pcc_rule->precedence);
                ogs_expect_or_return(pf);

                memcpy(&pf->rule, &rule, sizeof(smf_rule_t));
                pf->direction = flow->direction;
            }

            memset(&tft, 0, sizeof tft);
            if (pcc_rule->num_of_flow)
                encode_traffic_flow_template(&tft, bearer);

            memset(&h, 0, sizeof(ogs_gtp_header_t));
            if (bearer_created == 1) {
                h.type = OGS_GTP_CREATE_BEARER_REQUEST_TYPE;
                h.teid = sess->sgw_s5c_teid;

                /* TFT is mandatory in
                 * activate dedicated EPS bearer context request */
                ogs_assert(pcc_rule->num_of_flow);

                pkbuf = smf_s5c_build_create_bearer_request(
                        h.type, bearer, pcc_rule->num_of_flow ? &tft : NULL);
                ogs_expect_or_return(pkbuf);
            } else {
                h.type = OGS_GTP_UPDATE_BEARER_REQUEST_TYPE;
                h.teid = sess->sgw_s5c_teid;

                pkbuf = smf_s5c_build_update_bearer_request(
                        h.type, bearer,
                        OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED,
                        pcc_rule->num_of_flow ? &tft : NULL, qos_presence);
                ogs_expect_or_return(pkbuf);
            }

            xact = ogs_gtp_xact_local_create(
                    sess->gnode, &h, pkbuf, timeout, sess);
            ogs_expect_or_return(xact);

            rv = ogs_gtp_xact_commit(xact);
            ogs_expect(rv == OGS_OK);
        } else if (pcc_rule->type == OGS_PCC_RULE_TYPE_REMOVE) {
            bearer = smf_bearer_find_by_name(sess, pcc_rule->name);
            ogs_assert(bearer);

            if (!bearer) {
                ogs_warn("No need to send 'Delete Bearer Request'");
                ogs_warn("  - Bearer[Name:%s] has already been removed.",
                        pcc_rule->name);
                return;
            }

            memset(&h, 0, sizeof(ogs_gtp_header_t));
            h.type = OGS_GTP_DELETE_BEARER_REQUEST_TYPE;
            h.teid = sess->sgw_s5c_teid;

            pkbuf = smf_s5c_build_delete_bearer_request(h.type, bearer,
                    OGS_NAS_PROCEDURE_TRANSACTION_IDENTITY_UNASSIGNED);
            ogs_expect_or_return(pkbuf);

            xact = ogs_gtp_xact_local_create(
                    sess->gnode, &h, pkbuf, timeout, sess);
            ogs_expect_or_return(xact);

            rv = ogs_gtp_xact_commit(xact);
            ogs_expect(rv == OGS_OK);
        } else {
            ogs_error("Invalid Type[%d]", pcc_rule->type);
        }
    }
}
