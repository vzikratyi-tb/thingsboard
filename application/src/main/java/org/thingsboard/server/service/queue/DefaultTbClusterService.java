/**
 * Copyright © 2016-2020 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.server.service.queue;

import com.google.protobuf.ByteString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.thingsboard.rule.engine.api.msg.ToDeviceActorNotificationMsg;
import org.thingsboard.server.common.data.DeviceProfile;
import org.thingsboard.server.common.data.EntityType;
import org.thingsboard.server.common.data.HasName;
import org.thingsboard.server.common.data.Tenant;
import org.thingsboard.server.common.data.TenantProfile;
import org.thingsboard.server.common.data.id.DeviceId;
import org.thingsboard.server.common.data.id.DeviceProfileId;
import org.thingsboard.server.common.data.id.EntityId;
import org.thingsboard.server.common.data.id.RuleChainId;
import org.thingsboard.server.common.data.id.TenantId;
import org.thingsboard.server.common.data.id.TenantProfileId;
import org.thingsboard.server.common.data.plugin.ComponentLifecycleEvent;
import org.thingsboard.server.common.msg.TbMsg;
import org.thingsboard.server.common.msg.aware.EntityAwareMsg;
import org.thingsboard.server.common.msg.cache.AttributesCacheUpdatedMsg;
import org.thingsboard.server.common.msg.plugin.ComponentLifecycleMsg;
import org.thingsboard.server.common.msg.queue.ServiceType;
import org.thingsboard.server.common.msg.queue.TopicPartitionInfo;
import org.thingsboard.server.common.transport.util.DataDecodingEncodingService;
import org.thingsboard.server.gen.transport.TransportProtos;
import org.thingsboard.server.gen.transport.TransportProtos.FromDeviceRPCResponseProto;
import org.thingsboard.server.gen.transport.TransportProtos.ToCoreMsg;
import org.thingsboard.server.gen.transport.TransportProtos.ToCoreNotificationMsg;
import org.thingsboard.server.gen.transport.TransportProtos.ToRuleEngineMsg;
import org.thingsboard.server.gen.transport.TransportProtos.ToRuleEngineNotificationMsg;
import org.thingsboard.server.gen.transport.TransportProtos.ToTransportMsg;
import org.thingsboard.server.queue.TbQueueCallback;
import org.thingsboard.server.queue.TbQueueProducer;
import org.thingsboard.server.queue.common.TbProtoQueueMsg;
import org.thingsboard.server.queue.discovery.PartitionService;
import org.thingsboard.server.queue.provider.TbQueueProducerProvider;
import org.thingsboard.server.service.profile.TbDeviceProfileCache;
import org.thingsboard.server.service.rpc.FromDeviceRpcResponse;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

@Service
@Slf4j
public class DefaultTbClusterService implements TbClusterService {

    @Value("${cluster.stats.enabled:false}")
    private boolean statsEnabled;

    private final AtomicInteger toCoreMsgs = new AtomicInteger(0);
    private final AtomicInteger toCoreNfs = new AtomicInteger(0);
    private final AtomicInteger toRuleEngineMsgs = new AtomicInteger(0);
    private final AtomicInteger toRuleEngineNfs = new AtomicInteger(0);
    private final AtomicInteger toTransportNfs = new AtomicInteger(0);

    private final TbQueueProducerProvider producerProvider;
    private final PartitionService partitionService;
    private final DataDecodingEncodingService encodingService;
    private final TbDeviceProfileCache deviceProfileCache;

    public DefaultTbClusterService(TbQueueProducerProvider producerProvider, PartitionService partitionService, DataDecodingEncodingService encodingService, TbDeviceProfileCache deviceProfileCache) {
        this.producerProvider = producerProvider;
        this.partitionService = partitionService;
        this.encodingService = encodingService;
        this.deviceProfileCache = deviceProfileCache;
    }

    @Override
    public void pushMsgToCore(TenantId tenantId, EntityId entityId, ToCoreMsg msg, TbQueueCallback callback) {
        TopicPartitionInfo tpi = partitionService.resolve(ServiceType.TB_CORE, tenantId, entityId);
        producerProvider.getTbCoreMsgProducer().send(tpi, new TbProtoQueueMsg<>(UUID.randomUUID(), msg), callback);
        toCoreMsgs.incrementAndGet();
    }

    @Override
    public void pushMsgToCore(TopicPartitionInfo tpi, UUID msgId, ToCoreMsg msg, TbQueueCallback callback) {
        producerProvider.getTbCoreMsgProducer().send(tpi, new TbProtoQueueMsg<>(msgId, msg), callback);
        toCoreMsgs.incrementAndGet();
    }

    @Override
    public void pushMsgToCore(ToDeviceActorNotificationMsg msg, TbQueueCallback callback) {
        TopicPartitionInfo tpi = partitionService.resolve(ServiceType.TB_CORE, msg.getTenantId(), msg.getDeviceId());
        log.trace("PUSHING msg: {} to:{}", msg, tpi);
        byte[] msgBytes = encodingService.encode(msg);
        ToCoreMsg toCoreMsg = ToCoreMsg.newBuilder().setToDeviceActorNotificationMsg(ByteString.copyFrom(msgBytes)).build();
        producerProvider.getTbCoreMsgProducer().send(tpi, new TbProtoQueueMsg<>(msg.getDeviceId().getId(), toCoreMsg), callback);
        toCoreMsgs.incrementAndGet();
    }

    @Override
    public void pushNotificationToCore(String serviceId, FromDeviceRpcResponse response, TbQueueCallback callback) {
        TopicPartitionInfo tpi = partitionService.getNotificationsTopic(ServiceType.TB_CORE, serviceId);
        log.trace("PUSHING msg: {} to:{}", response, tpi);
        FromDeviceRPCResponseProto.Builder builder = FromDeviceRPCResponseProto.newBuilder()
                .setRequestIdMSB(response.getId().getMostSignificantBits())
                .setRequestIdLSB(response.getId().getLeastSignificantBits())
                .setError(response.getError().isPresent() ? response.getError().get().ordinal() : -1);
        response.getResponse().ifPresent(builder::setResponse);
        ToCoreNotificationMsg msg = ToCoreNotificationMsg.newBuilder().setFromDeviceRpcResponse(builder).build();
        producerProvider.getTbCoreNotificationsMsgProducer().send(tpi, new TbProtoQueueMsg<>(response.getId(), msg), callback);
        toCoreNfs.incrementAndGet();
    }

    @Override
    public void pushMsgToRuleEngine(TopicPartitionInfo tpi, UUID msgId, ToRuleEngineMsg msg, TbQueueCallback callback) {
        log.trace("PUSHING msg: {} to:{}", msg, tpi);
        producerProvider.getRuleEngineMsgProducer().send(tpi, new TbProtoQueueMsg<>(msgId, msg), callback);
        toRuleEngineMsgs.incrementAndGet();
    }

    @Override
    public void pushMsgToRuleEngine(TenantId tenantId, EntityId entityId, TbMsg tbMsg, TbQueueCallback callback) {
        if (tenantId.isNullUid()) {
            if (entityId.getEntityType().equals(EntityType.TENANT)) {
                tenantId = new TenantId(entityId.getId());
            } else {
                log.warn("[{}][{}] Received invalid message: {}", tenantId, entityId, tbMsg);
                return;
            }
        } else {
            if (entityId.getEntityType().equals(EntityType.DEVICE)) {
                tbMsg = transformMsg(tbMsg, deviceProfileCache.get(tenantId, new DeviceId(entityId.getId())));
            } else if (entityId.getEntityType().equals(EntityType.DEVICE_PROFILE)) {
                tbMsg = transformMsg(tbMsg, deviceProfileCache.get(tenantId, new DeviceProfileId(entityId.getId())));
            }
        }
        TopicPartitionInfo tpi = partitionService.resolve(ServiceType.TB_RULE_ENGINE, tenantId, entityId);
        log.trace("PUSHING msg: {} to:{}", tbMsg, tpi);
        ToRuleEngineMsg msg = ToRuleEngineMsg.newBuilder()
                .setTenantIdMSB(tenantId.getId().getMostSignificantBits())
                .setTenantIdLSB(tenantId.getId().getLeastSignificantBits())
                .setTbMsg(TbMsg.toByteString(tbMsg)).build();
        producerProvider.getRuleEngineMsgProducer().send(tpi, new TbProtoQueueMsg<>(tbMsg.getId(), msg), callback);
        toRuleEngineMsgs.incrementAndGet();
    }

    private TbMsg transformMsg(TbMsg tbMsg, DeviceProfile deviceProfile) {
        if (deviceProfile != null) {
            RuleChainId targetRuleChainId = deviceProfile.getDefaultRuleChainId();
            if (targetRuleChainId != null && !targetRuleChainId.equals(tbMsg.getRuleChainId())) {
                tbMsg = TbMsg.transformMsg(tbMsg, targetRuleChainId);
            }
        }
        return tbMsg;
    }

    @Override
    public void pushNotificationToRuleEngine(String serviceId, FromDeviceRpcResponse response, TbQueueCallback callback) {
        TopicPartitionInfo tpi = partitionService.getNotificationsTopic(ServiceType.TB_RULE_ENGINE, serviceId);
        log.trace("PUSHING msg: {} to:{}", response, tpi);
        FromDeviceRPCResponseProto.Builder builder = FromDeviceRPCResponseProto.newBuilder()
                .setRequestIdMSB(response.getId().getMostSignificantBits())
                .setRequestIdLSB(response.getId().getLeastSignificantBits())
                .setError(response.getError().isPresent() ? response.getError().get().ordinal() : -1);
        response.getResponse().ifPresent(builder::setResponse);
        ToRuleEngineNotificationMsg msg = ToRuleEngineNotificationMsg.newBuilder().setFromDeviceRpcResponse(builder).build();
        producerProvider.getRuleEngineNotificationsMsgProducer().send(tpi, new TbProtoQueueMsg<>(response.getId(), msg), callback);
        toRuleEngineNfs.incrementAndGet();
    }

    @Override
    public void pushNotificationToTransport(String serviceId, ToTransportMsg response, TbQueueCallback callback) {
        TopicPartitionInfo tpi = partitionService.getNotificationsTopic(ServiceType.TB_TRANSPORT, serviceId);
        log.trace("PUSHING msg: {} to:{}", response, tpi);
        producerProvider.getTransportNotificationsMsgProducer().send(tpi, new TbProtoQueueMsg<>(UUID.randomUUID(), response), callback);
        toTransportNfs.incrementAndGet();
    }

    @Override
    public void onEntityStateChange(TenantId tenantId, EntityId entityId, ComponentLifecycleEvent state) {
        log.trace("[{}] Processing {} state change event: {}", tenantId, entityId.getEntityType(), state);
        ComponentLifecycleMsg componentLifecycleMsg = new ComponentLifecycleMsg(tenantId, entityId, state);
        broadcast(componentLifecycleMsg,
                bytes -> ToCoreNotificationMsg.newBuilder().setComponentLifecycleMsg(bytes).build(),
                bytes -> ToRuleEngineNotificationMsg.newBuilder().setComponentLifecycleMsg(bytes).build(),
                componentLifecycleMsg.getEntityId().getEntityType().equals(EntityType.TENANT)
                        || componentLifecycleMsg.getEntityId().getEntityType().equals(EntityType.DEVICE_PROFILE));
    }

    @Override
    public void onAttributesCacheUpdated(TenantId tenantId, EntityId entityId, String scope, List<String> attributeKeys) {
        log.trace("[{}][{}] Processing attributes cache change: [{}][{}]", tenantId, entityId, scope, attributeKeys);
        AttributesCacheUpdatedMsg attributesCacheUpdatedMsg = new AttributesCacheUpdatedMsg(tenantId, entityId, scope, attributeKeys);
        broadcast(attributesCacheUpdatedMsg,
                bytes -> ToCoreNotificationMsg.newBuilder().setAttributesCacheUpdatedMsg(bytes).build(),
                bytes -> ToRuleEngineNotificationMsg.newBuilder().setAttributesCacheUpdatedMsg(bytes).build(),
                true);
    }

    @Override
    public void invalidateAttributesCache() {
        log.trace("Invalidating attributes cache");
        broadcast(AttributesCacheUpdatedMsg.INVALIDATE_ALL_CACHE_MSG,
                bytes -> ToCoreNotificationMsg.newBuilder().setAttributesCacheUpdatedMsg(bytes).build(),
                bytes -> ToRuleEngineNotificationMsg.newBuilder().setAttributesCacheUpdatedMsg(bytes).build(),
                true);
    }

    @Override
    public void onDeviceProfileChange(DeviceProfile deviceProfile, TbQueueCallback callback) {
        onEntityChange(deviceProfile.getTenantId(), deviceProfile.getId(), deviceProfile, callback);
    }

    @Override
    public void onTenantProfileChange(TenantProfile tenantProfile, TbQueueCallback callback) {
        onEntityChange(TenantId.SYS_TENANT_ID, tenantProfile.getId(), tenantProfile, callback);
    }

    @Override
    public void onTenantChange(Tenant tenant, TbQueueCallback callback) {
        onEntityChange(TenantId.SYS_TENANT_ID, tenant.getId(), tenant, callback);
    }

    @Override
    public void onDeviceProfileDelete(DeviceProfile entity, TbQueueCallback callback) {
        onEntityDelete(entity.getTenantId(), entity.getId(), entity.getName(), callback);
    }

    @Override
    public void onTenantProfileDelete(TenantProfile entity, TbQueueCallback callback) {
        onEntityDelete(TenantId.SYS_TENANT_ID, entity.getId(), entity.getName(), callback);
    }

    @Override
    public void onTenantDelete(Tenant entity, TbQueueCallback callback) {
        onEntityDelete(TenantId.SYS_TENANT_ID, entity.getId(), entity.getName(), callback);
    }

    public <T extends HasName> void onEntityChange(TenantId tenantId, EntityId entityid, T entity, TbQueueCallback callback) {
        log.trace("[{}][{}][{}] Processing [{}] change event", tenantId, entityid.getEntityType(), entityid.getId(), entity.getName());
        TransportProtos.EntityUpdateMsg entityUpdateMsg = TransportProtos.EntityUpdateMsg.newBuilder()
                .setEntityType(entityid.getEntityType().name())
                .setData(ByteString.copyFrom(encodingService.encode(entity))).build();
        ToTransportMsg transportMsg = ToTransportMsg.newBuilder().setEntityUpdateMsg(entityUpdateMsg).build();
        broadcast(transportMsg);
    }

    private void onEntityDelete(TenantId tenantId, EntityId entityId, String name, TbQueueCallback callback) {
        log.trace("[{}][{}][{}] Processing [{}] delete event", tenantId, entityId.getEntityType(), entityId.getId(), name);
        TransportProtos.EntityDeleteMsg entityDeleteMsg = TransportProtos.EntityDeleteMsg.newBuilder()
                .setEntityType(entityId.getEntityType().name())
                .setEntityIdMSB(entityId.getId().getMostSignificantBits())
                .setEntityIdLSB(entityId.getId().getLeastSignificantBits())
                .build();
        ToTransportMsg transportMsg = ToTransportMsg.newBuilder().setEntityDeleteMsg(entityDeleteMsg).build();
        broadcast(transportMsg);
    }

    private void broadcast(ToTransportMsg transportMsg) {
        TbQueueProducer<TbProtoQueueMsg<ToTransportMsg>> toTransportNfProducer = producerProvider.getTransportNotificationsMsgProducer();
        Set<String> tbTransportServices = partitionService.getAllServiceIds(ServiceType.TB_TRANSPORT);
        for (String transportServiceId : tbTransportServices) {
            TopicPartitionInfo tpi = partitionService.getNotificationsTopic(ServiceType.TB_TRANSPORT, transportServiceId);
            toTransportNfProducer.send(tpi, new TbProtoQueueMsg<>(UUID.randomUUID(), transportMsg), null);
            toTransportNfs.incrementAndGet();
        }
    }

    private void broadcast(EntityAwareMsg msg,
                           Function<ByteString, ToCoreNotificationMsg> toCoreNotificationBuilder,
                           Function<ByteString, ToRuleEngineNotificationMsg> toRuleEngineNotificationBuilder,
                           boolean pushToCore) {
        byte[] msgBytes = encodingService.encode(msg);
        TbQueueProducer<TbProtoQueueMsg<ToRuleEngineNotificationMsg>> toRuleEngineProducer = producerProvider.getRuleEngineNotificationsMsgProducer();
        Set<String> tbRuleEngineServices = new HashSet<>(partitionService.getAllServiceIds(ServiceType.TB_RULE_ENGINE));
        if (pushToCore) {
            TbQueueProducer<TbProtoQueueMsg<ToCoreNotificationMsg>> toCoreNfProducer = producerProvider.getTbCoreNotificationsMsgProducer();
            Set<String> tbCoreServices = partitionService.getAllServiceIds(ServiceType.TB_CORE);
            for (String serviceId : tbCoreServices) {
                TopicPartitionInfo tpi = partitionService.getNotificationsTopic(ServiceType.TB_CORE, serviceId);
                ToCoreNotificationMsg toCoreMsg = toCoreNotificationBuilder.apply(ByteString.copyFrom(msgBytes));
                toCoreNfProducer.send(tpi, new TbProtoQueueMsg<>(msg.getEntityId().getId(), toCoreMsg), null);
                toCoreNfs.incrementAndGet();
            }
            // No need to push notifications twice
            tbRuleEngineServices.removeAll(tbCoreServices);
        }
        for (String serviceId : tbRuleEngineServices) {
            TopicPartitionInfo tpi = partitionService.getNotificationsTopic(ServiceType.TB_RULE_ENGINE, serviceId);
            ToRuleEngineNotificationMsg toRuleEngineMsg = toRuleEngineNotificationBuilder.apply(ByteString.copyFrom(msgBytes));
            toRuleEngineProducer.send(tpi, new TbProtoQueueMsg<>(msg.getEntityId().getId(), toRuleEngineMsg), null);
            toRuleEngineNfs.incrementAndGet();
        }
    }

    @Scheduled(fixedDelayString = "${cluster.stats.print_interval_ms}")
    public void printStats() {
        if (statsEnabled) {
            int toCoreMsgCnt = toCoreMsgs.getAndSet(0);
            int toCoreNfsCnt = toCoreNfs.getAndSet(0);
            int toRuleEngineMsgsCnt = toRuleEngineMsgs.getAndSet(0);
            int toRuleEngineNfsCnt = toRuleEngineNfs.getAndSet(0);
            int toTransportNfsCnt = toTransportNfs.getAndSet(0);
            if (toCoreMsgCnt > 0 || toCoreNfsCnt > 0 || toRuleEngineMsgsCnt > 0 || toRuleEngineNfsCnt > 0 || toTransportNfsCnt > 0) {
                log.info("To TbCore: [{}] messages [{}] notifications; To TbRuleEngine: [{}] messages [{}] notifications; To Transport: [{}] notifications",
                        toCoreMsgCnt, toCoreNfsCnt, toRuleEngineMsgsCnt, toRuleEngineNfsCnt, toTransportNfsCnt);
            }
        }
    }
}
