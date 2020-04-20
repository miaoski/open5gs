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

#include "ogs-pfcp.h"

int __ogs_pfcp_domain;

const char *ogs_pfcp_cause_get_name(uint8_t cause)
{
    switch(cause) {
    case OGS_PFCP_CAUSE_REQUEST_ACCEPTED:
        return "OGS_PFCP_CAUSE_REQUEST_ACCEPTED";
        break;
    case OGS_PFCP_CAUSE_REQUEST_REJECTED:
        return "OGS_PFCP_CAUSE_REQUEST_REJECTED";
        break;
    case OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND:
        return "OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND";
        break;
    case OGS_PFCP_CAUSE_MANDATORY_IE_MISSING:
        return "OGS_PFCP_CAUSE_MANDATORY_IE_MISSING";
        break;
    case OGS_PFCP_CAUSE_CONDITIONAL_IE_MISSING:
        return "OGS_PFCP_CAUSE_CONDITIONAL_IE_MISSING";
        break;
    case OGS_PFCP_CAUSE_INVALID_LENGTH:
        return "OGS_PFCP_CAUSE_INVALID_LENGTH";
        break;
    case OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT:
        return "OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT";
        break;
    case OGS_PFCP_CAUSE_INVALID_FORWARDING_POLICY:
        return "OGS_PFCP_CAUSE_INVALID_FORWARDING_POLICY";
        break;
    case OGS_PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION:
        return "OGS_PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION";
        break;
    case OGS_PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION:
        return "OGS_PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION";
        break;
    case OGS_PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE:
        return "OGS_PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE";
        break;
    case OGS_PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION:
        return "OGS_PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION";
        break;
    case OGS_PFCP_CAUSE_NO_RESOURCES_AVAILABLE:
        return "OGS_PFCP_CAUSE_NO_RESOURCES_AVAILABLE";
        break;
    case OGS_PFCP_CAUSE_SERVICE_NOT_SUPPORTED:
        return "OGS_PFCP_CAUSE_SERVICE_NOT_SUPPORTED";
        break;
    case OGS_PFCP_CAUSE_SYSTEM_FAILURE:
        return "OGS_PFCP_CAUSE_SYSTEM_FAILURE";
        break;
    default:
        break;
    }
    return "OGS_PFCP_CAUSE_UNKNOWN";
}

int16_t ogs_pfcp_build_user_plane_ip_resource(
        ogs_tlv_octet_t *octet,
        ogs_pfcp_user_plane_ip_resource_t *user_plane_ip_resource,
        void *data, int data_len)
{
    ogs_pfcp_user_plane_ip_resource_t target;
    int16_t size = 0;

    ogs_assert(user_plane_ip_resource);
    ogs_assert(octet);
    ogs_assert(data);
    ogs_assert(data_len);

    octet->data = data;
    memcpy(&target, user_plane_ip_resource,
            sizeof(ogs_pfcp_user_plane_ip_resource_t));

    ogs_assert(size + sizeof(target.flags) <= data_len);
    memcpy((unsigned char *)octet->data + size,
            &target.flags, sizeof(target.flags));
    size += sizeof(target.flags);

    if (target.teidri) {
        ogs_assert(size + sizeof(target.teid_range) <= data_len);
        memcpy((unsigned char *)octet->data + size,
                &target.teid_range, sizeof(target.teid_range));
        size += sizeof(target.teid_range);
    }

    if (target.v4) {
        ogs_assert(size + sizeof(target.addr) <= data_len);
        memcpy((unsigned char *)octet->data + size,
                &target.addr, sizeof(target.addr));
        size += sizeof(target.addr);
    }

    if (target.v6) {
        ogs_assert(size + OGS_IPV6_LEN <= data_len);
        memcpy((unsigned char *)octet->data + size,
                &target.addr6, OGS_IPV6_LEN);
        size += OGS_IPV6_LEN;
    }

    if (target.assoni) {
        int len = ogs_fqdn_build((char *)octet->data + size,
                target.network_instance, strlen(target.network_instance));
        size += len;
    }

    if (target.assosi) {
        ogs_assert(size + sizeof(target.source_interface) <= data_len);
        memcpy((unsigned char *)octet->data + size,
                &target.source_interface, sizeof(target.source_interface));
        size += sizeof(target.source_interface);
    }

    octet->len = size;

    return octet->len;
}

int16_t ogs_pfcp_parse_user_plane_ip_resource(
        ogs_pfcp_user_plane_ip_resource_t *user_plane_ip_resource,
        ogs_tlv_octet_t *octet)
{
    ogs_pfcp_user_plane_ip_resource_t *source = octet->data;
    int16_t size = 0;

    ogs_assert(user_plane_ip_resource);
    ogs_assert(octet);

    memset(user_plane_ip_resource, 0,
            sizeof(ogs_pfcp_user_plane_ip_resource_t));

    user_plane_ip_resource->flags = source->flags;
    size++;

    if (user_plane_ip_resource->teidri) {
        ogs_assert(size + sizeof(user_plane_ip_resource->teid_range) <=
                octet->len);
        memcpy(&user_plane_ip_resource->teid_range,
                (unsigned char *)octet->data + size,
                sizeof(user_plane_ip_resource->teid_range));
        size += sizeof(user_plane_ip_resource->teid_range);
    }

    if (user_plane_ip_resource->v4) {
        ogs_assert(size + sizeof(user_plane_ip_resource->addr) <= octet->len);
        memcpy(&user_plane_ip_resource->addr,
                (unsigned char *)octet->data + size,
                sizeof(user_plane_ip_resource->addr));
        size += sizeof(user_plane_ip_resource->addr);
    }

    if (user_plane_ip_resource->v6) {
        ogs_assert(size + OGS_IPV6_LEN <= octet->len);
        memcpy(&user_plane_ip_resource->addr6,
                (unsigned char *)octet->data + size, OGS_IPV6_LEN);
        size += OGS_IPV6_LEN;
    }

    if (user_plane_ip_resource->assoni) {
        int len = octet->len - size;
        if (user_plane_ip_resource->assosi) len--;

        ogs_fqdn_parse(user_plane_ip_resource->network_instance, 
                (char *)octet->data + size, len);
        size += len;
    }

    if (user_plane_ip_resource->assosi) {
        ogs_assert(size + sizeof(user_plane_ip_resource->source_interface) <=
                octet->len);
        memcpy(&user_plane_ip_resource->source_interface,
                (unsigned char *)octet->data + size,
                sizeof(user_plane_ip_resource->source_interface));
        size += sizeof(user_plane_ip_resource->source_interface);
    }

    ogs_assert(size == octet->len);

    return size;
}
