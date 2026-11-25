/**
 * Single-pane health collection for Catalyst 1200/1300 switches.
 *
 * The OID set here is deliberately small and chosen for signal: every entry
 * either answers "is the box healthy right now" or is needed to interpret
 * one that does. Everything is verified present in the 4.1.9.85 MIB set.
 *
 * Interfaces come from rlifPresentTable rather than ifTable, per the
 * 4.1.9.85 release notes -- ifTable also lists interfaces that do not
 * physically exist in the stack.
 */

const products = require('./products');

const snmp = require('net-snmp');

// --- scalars: one GET each, batched -------------------------------------
const SYSTEM_OIDS = [
  'sysDescr.0', 'sysName.0', 'sysUpTime.0', 'sysLocation.0', 'sysContact.0'
];

const HEALTH_SCALARS = [
  'rlEnvSystemLed.0',                 // front-panel status LED: green/amber
  'rlCpuUtilDuringLastSecond.0',
  'rlCpuUtilDuringLastMinute.0',
  'rlCpuUtilDuringLast5Minutes.0',
  // Packets per second the CPU is handling. Read the enable flag too:
  // when SCT rate counting is off the rate reads zero, which would
  // otherwise look like an idle control plane rather than "not measured".
  'rlSctCpuRate.0',
  'rlSctCpuRateEnabled.0',
  'rlFileTotalSizeOfFlash.0',
  'rlFileFreeSizeOfFlash.0',
  'rlRunningCDBequalToStartupCDB.0',  // unsaved running-config
  // IP Routing & DNS global status.
  'ipForwarding.0',                   // global L3 forwarding: forwarding(1)/notForwarding(2)
  'rlDnsClEnable.0',                  // DNS client enabled/disabled
  // Voice VLAN globals (CISCOSB-vlanvoice.mib, base ...48.54).
  'vlanVoiceAdminState.0',            // disabled(0)/auto-enabled(1)/auto-triggered(2)/oui-enabled(3)
  'vlanVoiceOperState.0',
  'vlanVoiceAdminVid.0', 'vlanVoiceOperVid.0',
  'vlanVoiceAutoAdminVpt.0', 'vlanVoiceAutoAdminDscp.0',   // admin CoS / DSCP
  'vlanVoiceAutoOperVpt.0', 'vlanVoiceAutoOperDscp.0',     // oper CoS / DSCP
  'vlanVoiceOUIBasedAdminPriority.0', 'vlanVoiceOUIBasedAdminRemark.0',
  'vlanVoiceOUIBasedAgingTimeout.0',  // minutes (1..43200)
  // AAA global state and defaults, shown with the server tables.
  'rlAAARadiusEnabled.0', 'rlAAATacacsEnabled.0',
  'rlRadiusGlobalDefaultTimeout.0', 'rlRadiusGlobalDefaultRetries.0', 'rlRadiusGlobalDefaultDeadtime.0',
  'rlTacacsGlobalDefaultTimeout.0',
  // Port-channel (LAG) limits.
  'rlDot3adAggNumOfTrunks.0', 'rlDot3adAggMaxPortsInTrunks.0',
  // 802.1X global settings (shown in Sessions & authentication).
  'dot1xPaeSystemAuthControl.0',          // global port-based auth enable
  'rldot1xGuestVlanVID.0', 'rldot1xGuestVlanTimeInterval.0',
  'rldot1xMacAuthSuccessTrapEnabled.0', 'rldot1xMacAuthFailureTrapEnabled.0',
  'rldot1xSupplicantSuccessTrapEnabled.0', 'rldot1xSupplicantFailureTrapEnabled.0',
  'rldot1xMacWebAuthSuccessTrapEnabled.0', 'rldot1xMacWebAuthFailureTrapEnabled.0',  // per-method trap enums
  'rldot1xWebQuietFailureTrapEnabled.0',
  'rldot1xGuestVlanPorts.0',  // PortList bitmap: ports with guest VLAN enabled
  'vlanVoiceOperVid.0',       // voice VLAN (excluded from guest-VLAN choices)
  // MAB (MAC Authentication Bypass) global settings: username format + password.
  'rldot1xMacAuthEapEnabled.0', 'rldot1xMacAuthUserGroupsize.0',
  'rldot1xMacAuthUserSeparator.0', 'rldot1xMacAuthUserLowercase.0'
];

// Spanning tree, from the standard BRIDGE-MIB. These apply whatever mode
// the switch is in; the per-mode detail is walked conditionally below.
const STP_SCALARS = [
  'dot1dStpProtocolSpecification.0', 'dot1dStpVersion.0', 'dot1dStpPriority.0',
  'dot1dStpDesignatedRoot.0', 'dot1dStpRootCost.0', 'dot1dStpRootPort.0',
  'dot1dStpTopChanges.0', 'dot1dStpTimeSinceTopologyChange.0',
  'dot1dStpMaxAge.0', 'dot1dStpHelloTime.0', 'dot1dStpForwardDelay.0',
  'dot1dBaseBridgeAddress.0'
];

// --- tables: walked ------------------------------------------------------
// Anything a show tech-support capture can tell you that SNMP can tell you
// too is polled here, so the dashboard is fully populated without needing a
// capture. maxRows caps the walks that can be large on a busy switch --
// the forwarding database in particular.
/**
 * Walking a table walks every column in it, and most tables carry far more
 * than any panel shows: rlifPresentTable has forty columns and the
 * Interfaces panel uses seven. Naming the columns turns one broad walk
 * into a few narrow ones -- fewer varbinds *and* fewer round trips, since
 * each column walk fills its GETBULK responses with rows rather than with
 * columns nobody asked for.
 *
 * Tables small enough that the request count would dominate are left
 * whole; a five-row table is not worth four walks.
 */
/*
 * Two markers decide how a table is read (SERVER-STANDARD §1a):
 *
 *  perPort: 'ifIndex' | 'bridgePort' -- the table has one row per port, and
 *    the switch answers for every slot of its ifIndex space (424 rows on a
 *    24-port C1300, against 40 interfaces that exist). Rather than walk them
 *    all and throw the empty slots away, the rows of the interfaces that
 *    rlifPresentTable lists are fetched by GET. 'bridgePort' tables are indexed
 *    by bridge port, which dot1dBasePortTable maps to the ifIndex.
 *  settings: true -- configuration that only changes when someone changes it.
 *    The collector carries the last copy forward between full reads (`reuse`)
 *    and re-reads it after a config change, a reboot, an app write, a manual
 *    Refresh, or an hour.
 */
const TABLE_WALKS = {
  // Keys must match the property names buildAlerts()/summarise() read.
  psus:       { oid: 'rlEnvMonSupplyStatusTable' },
  fans:       { oid: 'rlEnvMonFanStatusTable' },
  fanData:    { oid: 'rlEnvFanDataTable' },
  sensors:    { oid: 'entPhySensorTable' },
  stack:      { oid: 'rlPhdStackTable' },
  poe:        { oid: 'pethMainPseTable' },
  poePorts:   { oid: 'pethPsePortTable', columns: [
    'pethPsePortAdminEnable', 'pethPsePortDetectionStatus', 'pethPsePortPowerClassifications',
    'pethPsePortPowerPriority', 'pethPsePortPowerDeniedCounter'] },
  interfaces: { oid: 'rlifPresentTable', columns: [
    'rlifPresentName', 'rlifPresentDescr', 'rlifPresentAlias', 'rlifPresentAdminStatus',
    'rlifPresentOperStatus', 'rlifPresentHighSpeed', 'rlifPresentInErrors', 'rlifPresentOutErrors',
    // Extra per-port detail surfaced in the click-through popout (not columns).
    'rlifPresentPhysAddress', 'rlifPresentMtu', 'rlifPresentType', 'rlifPresentLastChange'] },
  // Switchport mode per port, from vlanPortModeState (CISCOSB vlanPortModeTable),
  // indexed by ifIndex. Confirmed on this switch against the CLI: value 11 is
  // access, 12 is trunk. Other values are shown raw rather than mislabeled.
  portModes:  { perPort: 'ifIndex', oid: 'vlanPortModeTable', maxRows: 1000, columns: ['vlanPortModeState'] },
  // Per-port configured access VLAN and trunk native VLAN. These reflect the
  // port's CONFIGURED membership even when the port is down (the static egress
  // tables only show applied membership once the port is up), so they are the
  // authoritative source for what VLAN a switchport is set to.
  portAccessVlan: { perPort: 'ifIndex', oid: 'vlanAccessPortModeTable', maxRows: 1000, columns: ['vlanAccessPortModeVlanId'] },
  portNativeVlan: { perPort: 'ifIndex', oid: 'vlanTrunkPortModeTable', maxRows: 1000, columns: ['vlanTrunkPortModeNativeVlanId'] },
  // Whether each port is an L2 switchport or an L3 routed port, from the CISCOSB
  // vlanSwitchPortModeTable (vlanSwitchPortModeCategory), indexed by ifIndex.
  // Enum: 1 = l2 (switchport), 2 = l3 (no switchport / routed).
  portL2L3:   { perPort: 'ifIndex', oid: 'vlanSwitchPortModeTable', maxRows: 1000, columns: ['vlanSwitchPortModeCategory'] },

  // Equivalents for data that used to come only from a capture:
  inventory:  { settings: true, oid: 'entPhysicalTable', maxRows: 2000, columns: [
    'entPhysicalDescr', 'entPhysicalClass', 'entPhysicalName', 'entPhysicalHardwareRev',
    'entPhysicalSoftwareRev', 'entPhysicalSerialNum', 'entPhysicalModelName'] },
  vlans:      { oid: 'dot1qVlanStaticTable', maxRows: 4096, columns: [
    'dot1qVlanStaticName', 'dot1qVlanStaticEgressPorts', 'dot1qVlanStaticUntaggedPorts'] },
  // Voice VLAN Telephony OUI table (editable): index is the 3-byte OUI prefix;
  // Description is the only readable value (RowStatus too). The prefix is read
  // from the row index.
  voiceOUI:   { settings: true, oid: 'vlanVoiceOUIBasedTable', maxRows: 128, columns: [
    'vlanVoiceOUIBasedDescription', 'vlanVoiceOUIBasedEntryRowStatus'] },
  // Voice VLAN local source (UC Device) table - read-only display. Index is a
  // row id; all fields are readable columns.
  voiceLocalSrc: { oid: 'vlanVoiceUcDeviceTable', maxRows: 256, columns: [
    'vlanVoiceUcDeviceType', 'vlanVoiceUcDeviceMacAddress', 'vlanVoiceUcDeviceInterface',
    'vlanVoiceUcDeviceVid', 'vlanVoiceUcDeviceVpt', 'vlanVoiceUcDeviceDscp', 'vlanVoiceUcDeviceIsBest'] },
  cdp:        { oid: 'cdpCacheTable', maxRows: 1000, columns: [
    'cdpCacheAddress', 'cdpCacheDeviceId', 'cdpCacheDevicePort', 'cdpCachePlatform'] },
  lldp:       { oid: 'lldpRemTable', maxRows: 1000, columns: [
    'lldpRemChassisId', 'lldpRemPortId', 'lldpRemPortDesc', 'lldpRemSysName'] },
  // The MAC forwarding database is large and only shown in the Connected panel,
  // so it is fetched on demand by that panel's refresh (onDemand), not on every
  // full health poll.
  // The MAC table is large (thousands of entries across VLANs) but it is a
  // simple, well-behaved standard table, so it can use a much higher GETBULK
  // repetition count than the conservative default - fewer round-trips for the
  // same data. maxRows is raised so a big forwarding database isn't truncated.
  macTable:   { oid: 'dot1qTpFdbTable', maxRows: 8000, onDemand: true, maxRepetitions: 40, columns: [
    'dot1qTpFdbPort', 'dot1qTpFdbStatus'] },
  // Standard IP ACL rules (rlIpStdAclTable, indexed by ACL name + ACE index).
  // On-demand: only walked when the ACL panel asks for it.
  // SVI / IP interface addresses (rsIpAddrTable). Small table, so it rides the
  // regular poll - gives the VLAN view each SVI's IPv4 address. Indexed by the
  // IP address; the columns tell us the owning ifIndex, mask, and owner.
  sviAddrs:   { oid: 'rsIpAddrTable', maxRows: 256, columns: [
    'rsIpAdEntIfIndex', 'rsIpAdEntNetMask', 'rsIpAdEntOwner'] },

  // ---- IP Routing & DNS (own module) ----
  // The full IP forwarding table (RFC 2096 ipCidrRouteTable): connected,
  // static, local and any dynamic routes, each with its protocol and type.
  // Can be large on a routing switch, so it is paginated in the UI.
  routeTable: { oid: 'ipCidrRouteTable', maxRows: 4000, onDemand: true, columns: [
    'ipCidrRouteDest', 'ipCidrRouteMask', 'ipCidrRouteNextHop',
    'ipCidrRouteIfIndex', 'ipCidrRouteType', 'ipCidrRouteProto', 'ipCidrRouteStatus'] },
  // User-configured static routes (the editable set). IPv4, plain IpAddress
  // indices - simpler than the inet-typed table and right for this model.
  staticRoutes: { settings: true, oid: 'rlIpStaticRouteTable', maxRows: 1000, columns: [
    'rlIpStaticRouteDest', 'rlIpStaticRouteMask', 'rlIpStaticRouteNextHop',
    'rlIpStaticRouteType', 'rlIpStaticRouteMetric', 'rlIpStaticRouteOwner',
    'rlIpStaticRouteForwardingStatus'] },
  // DNS domain / search-suffix list.
  dnsDomains: { settings: true, oid: 'rlDnsClDomainNameTable', maxRows: 64, columns: [
    'rlDnsClDomainNameOwner'] },
  // Configured nameservers. The Cisco rlDnsResConfigSbeltInetTable is the
  // writable one on this model (the standard MIB-II sbelt is read-only), and we
  // read from the same table we write to so the list and the edits agree.
  // The DNS-client-v2 servers table (rlDnsClv2ServersTable) - the one the CLI
  // "ip name-server" actually writes, and the one a server delete must target
  // (the sbelt table rejects every delete). Everything about a server lives in
  // the row index (address, source, preference, class are all index columns);
  // only RowStatus is a readable value, so the row is driven entirely off index.
  dnsServersV2: { settings: true, oid: 'rlDnsClv2ServersTable', maxRows: 64, columns: [
    'rlDnsClv2ServersRowStatus'] },
  // Nameservers come from the DNS-client-v2 servers table (dnsServersV2, 93.15),
  // the table the CLI "ip name-server" uses. The old sbelt tables
  // (rlDnsResConfigSbeltInetTable 93.9 + its Ext/DHCP companions) were the
  // original read source but are a read-only reflection of the v2 rows, so they
  // were removed from the walk once the panel moved to v2 - the add path still
  // writes 93.9 (it propagates into v2), but nothing reads the sbelt tables.
  // Static host-name -> IP mappings (the switch's local hosts file).
  dnsHosts: { settings: true, oid: 'rlDnsClNamesTable', maxRows: 256, columns: [
    'rlDnsClNamesIndex', 'rlDnsClNamesAddr'] },
  // QoS ACL panel (rlQosAcl 88.7 / 88.31 / 88.5). These three tables are joined
  // client-side (ACL header -> ACEs -> tuple values via pointer indirection), so
  // they are walked in RAW mode: health returns the un-pivoted walk rows the
  // panel's existing join reads ({ index, column, value }). onDemand - loaded on
  // first panel visit, cheap (~6 PDUs), refreshed on write in place.
  aclNames:  { raw: true, onDemand: true, maxRows: 2000, oid: '1.3.6.1.4.1.9.6.1.101.88.7.1' },     // name(.2)+type(.3)
  aclAces:   { raw: true, onDemand: true, maxRows: 4000, oid: '1.3.6.1.4.1.9.6.1.101.88.31' },      // ACE table (action/type/tuple ptrs)
  aclTuples: { raw: true, onDemand: true, maxRows: 4000, oid: '1.3.6.1.4.1.9.6.1.101.88.5' },       // tuple values
  bridgePorts: { perPort: 'ifIndex', oid: 'dot1dBasePortTable', maxRows: 1000, columns: ['dot1dBasePortIfIndex'] },
  // The operational VLAN table. Switches populate this even when the
  // static table is sparse, which is why membership has to come from here
  // and only the names from the static one.
  vlansCurrent: { oid: 'dot1qVlanCurrentTable', maxRows: 4096, columns: [
    'dot1qVlanCurrentEgressPorts', 'dot1qVlanCurrentUntaggedPorts'] },
  // Who is on the switch, and who has authenticated to get onto the
  // network through it. Both are small tables and neither is fetched
  // anywhere else, so they come with the ordinary collection.
  mgmtSessions: { oid: 'rlSecSdMngSessionsTable', maxRows: 100 },
  sshSessions: { oid: 'rlSshServerSessionInetTable', maxRows: 100 },
  telnetSessions: { oid: 'rlTelnetUsersTable', maxRows: 100 },
  dot1xHosts: { oid: 'rldot1xAuthMultiSessionStatsTable', maxRows: 2000, columns: [
    'rldot1xAuthMultiSessionId', 'rldot1xAuthMultiSessionTime', 'rldot1xAuthMultiSessionUserName',
    'rldot1xAuthMultiSessionRadiusAttrVlan', 'rlDot1xAuthMultiSessionMethodType'] },
  dot1xLocked: { oid: 'rldot1xLockedCientsTable', maxRows: 500 },
  // Per-port 802.1X configuration: port-control mode (force-unauth/auto/
  // force-auth) and the current authorized/unauthorized status, plus the
  // host-mode (single / multiple / multiple-auth) from the interface table.
  dot1xPortCfg: { perPort: 'ifIndex', oid: 'dot1xAuthConfigTable', maxRows: 1000, columns: [
    'dot1xAuthAuthControlledPortControl', 'dot1xAuthAuthControlledPortStatus'] },
  // Per-port authentication method (802.1X / MAC(MAB) / Web combinations), the
  // per-port MAB enable, shown and editable in the interface 802.1X section.
  dot1xPortMethod: { perPort: 'ifIndex', oid: 'rldot1xAuthenticationPortTable', maxRows: 1000, columns: [
    'rldot1xAuthenticationPortMethod'] },
  // swIfTable host-mode only (shown in the main table's 802.1X column). The
  // editable physical settings (speed, duplex, auto-neg, flow, MDIX) and the
  // port alias are NOT polled here - they appear only in the per-port popout,
  // so they are fetched on demand for that one port when it is opened. Keeping
  // them out of the regular poll avoids walking swIfTable/ifXTable on every
  // interface refresh, which was loading the CPU.
  dot1xHostMode: { perPort: 'ifIndex', oid: 'swIfTable', maxRows: 1000, columns: ['swIfHostMode'] },
  // Port channels (LAGs). The creation table lists every aggregator slot the
  // switch supports (static/LACP flags); the standard dot3ad tables give the
  // key, aggregating status, system id, and the member-port bitmap. Member
  // assignment is per physical port's actor admin key.
  lagCreation: { settings: true, oid: 'rlDot3adAggCreationTable', maxRows: 128, columns: [
    'rlDot3adAggCreationTrunk', 'rlDot3adAggCreationLacp'] },
  lagAgg: { oid: 'dot3adAggTable', maxRows: 128, columns: [
    'dot3adAggActorAdminKey', 'dot3adAggActorOperKey', 'dot3adAggAggregateOrIndividual',
    'dot3adAggActorSystemID'] },
  lagMembers: { oid: 'dot3adAggPortListTable', maxRows: 128, columns: ['dot3adAggPortListPorts'] },
  lagPortKey: { perPort: 'ifIndex', oid: 'dot3adAggPortTable', maxRows: 1000, columns: [
    'dot3adAggPortActorAdminKey', 'dot3adAggPortSelectedAggID', 'dot3adAggPortAttachedAggID',
    'dot3adAggPortActorAdminState'] },
  // Curated per-host (port+MAC) 802.1X counters: EAPOL frame totals, the key
  // state-machine auth outcomes, and session octet/frame totals.
  dot1xHostStats: { oid: 'rldot1xAuthMultiStatsTable', maxRows: 2000, columns: [
    'rldot1xAuthMultiEapolFramesRx', 'rldot1xAuthMultiEapolFramesTx',
    'rldot1xAuthMultiEapolStartFramesRx', 'rldot1xAuthMultiEapolLogoffFramesRx',
    'rldot1xAuthMultiInvalidEapolFramesRx'] },
  dot1xHostDiag: { oid: 'rldot1xAuthMultiDiagTable', maxRows: 2000, columns: [
    'rldot1xAuthMultiAuthSuccessWhileAuthenticating', 'rldot1xAuthMultiAuthFailWhileAuthenticating',
    'rldot1xAuthMultiBackendAuthSuccesses', 'rldot1xAuthMultiBackendAccessChallenges'] },
  // Per-host 802.1X session: traffic counters plus the richer session detail
  // (session id, assigned VLAN/filter, source IP, reauth time remaining) that
  // the host detail popout shows.
  dot1xHostSession: { oid: 'rldot1xAuthMultiSessionStatsTable', maxRows: 2000, columns: [
    'rldot1xAuthMultiSessionOctetsRx', 'rldot1xAuthMultiSessionOctetsTx',
    'rldot1xAuthMultiSessionFramesRx', 'rldot1xAuthMultiSessionFramesTx',
    'rldot1xAuthMultiSessionId', 'rldot1xAuthMultiSessionSourceIpAddress',
    'rldot1xAuthMultiSessionReauthTimeRemain', 'rldot1xAuthMultiSessionRadiusAttrVlan',
    'rldot1xAuthMultiSessionRadiusAttrFilterId', 'rldot1xAuthMultiSessionAcctSessionId'] },
  // AAA servers (RADIUS + TACACS+): configured servers, their live state, and
  // the standard RFC 4668 RADIUS client statistics. Small tables, collected
  // with the auth data since that is where they are shown.
  radiusServers: { settings: true, oid: 'rlRadiusServerInetTable', maxRows: 64, columns: [
    'rlRadiusServerInetAddress', 'rlRadiusServerInetAuthPortNumber', 'rlRadiusServerInetAcctPortNumber',
    'rlRadiusServerInetTimeout', 'rlRadiusServerInetRetries', 'rlRadiusServerInetDeadtime',
    'rlRadiusServerInetPriority', 'rlRadiusServerInetUsage', 'rlRadiusServerInetUseGlobalDefaultKey',
    'rlRadiusServerInetKey', 'rlRadiusServerInetSource'] },
  radiusStats: { oid: 'radiusAuthServerTable', maxRows: 64, columns: [
    'radiusAuthServerAddress', 'radiusAuthClientServerPortNumber', 'radiusAuthClientRoundTripTime',
    'radiusAuthClientAccessRequests', 'radiusAuthClientAccessRetransmissions', 'radiusAuthClientAccessAccepts',
    'radiusAuthClientAccessRejects', 'radiusAuthClientAccessChallenges', 'radiusAuthClientMalformedAccessResponses',
    'radiusAuthClientBadAuthenticators', 'radiusAuthClientPendingRequests', 'radiusAuthClientTimeouts',
    'radiusAuthClientUnknownTypes', 'radiusAuthClientPacketsDropped'] },
  tacacsServers: { settings: true, oid: 'rlTacacsServerInetTable', maxRows: 64, columns: [
    'rlTacacsServerInetAddress', 'rlTacacsServerInetPortNumber', 'rlTacacsServerInetConnectionType',
    'rlTacacsServerInetConnectionStatus', 'rlTacacsServerInetTimeout', 'rlTacacsServerInetPriority',
    'rlTacacsServerInetUseGlobalDefaultKey', 'rlTacacsServerInetKey'] },
  stpPorts: { perPort: 'bridgePort', oid: 'dot1dStpPortTable', maxRows: 1000, columns: [
    'dot1dStpPortState', 'dot1dStpPortEnable', 'dot1dStpPortPathCost', 'dot1dStpPortPriority',
    'dot1dStpPortDesignatedBridge', 'dot1dStpPortDesignatedPort',
    'dot1dStpPortForwardTransitions'] },
  stpExtPorts: { perPort: 'bridgePort', oid: 'dot1dStpExtPortTable', maxRows: 1000, columns: [
    'dot1dStpPortOperEdgePort', 'dot1dStpPortOperPointToPoint'] },
  // Always walked, and small: one row per VLAN or per MST instance. These
  // are what actually decide which spanning-tree family is running --
  // see stpFamily() for why the version scalar is not trusted alone.
  pvstVlans: { oid: 'rlBrgPvstOperVlanTable', maxRows: 4096 },
  mstpInstances: { oid: 'rldot1sMstpInstanceTable', maxRows: 200 }
};

// The tables the collector may carry between full reads (see `settings`).
const SETTINGS_TABLES = Object.keys(TABLE_WALKS).filter((k) => TABLE_WALKS[k].settings);

// Walked only when the switch is running the matching mode: under MSTP the
// PVST tables are empty and vice versa, so walking both wastes round trips.
const MODE_WALKS = {
  mstp: {},
  pvst: {
    // The vendor table (correct name is ...PortTable) and the standard
    // Cisco one; switches populate one or the other depending on which
    // protection feature blocked the port.
    pvstInconsistencies: { oid: 'rlBrgPvstInconsistencyPortTable', maxRows: 500 },
    stpxInconsistencies: { oid: 'stpxInconsistencyTable', maxRows: 500 }
  }
};
const MSTP_SCALARS = ['rldot1sMstpConfigurationName.0', 'rldot1sMstpConfigurationDigest.0',
  'rldot1sMstpDesignatedMaxHopes.0'];

/**
 * Not every switch populates rlifPresentTable. Without it there is no way
 * to name a port or to tell a real one from an empty slot in the ifIndex
 * space, which is how a per-VLAN table ends up either full of phantoms or
 * completely empty. IF-MIB is the fallback: it lists only interfaces the
 * switch actually has, and the columns map one-for-one onto the ones the
 * panels already read.
 */
const IF_MIB_FALLBACK = {
  rlifPresentName: '1.3.6.1.2.1.31.1.1.1.1',        // ifName
  rlifPresentDescr: '1.3.6.1.2.1.2.2.1.2',          // ifDescr
  rlifPresentAdminStatus: '1.3.6.1.2.1.2.2.1.7',
  rlifPresentOperStatus: '1.3.6.1.2.1.2.2.1.8',
  rlifPresentHighSpeed: '1.3.6.1.2.1.31.1.1.1.15',
  rlifPresentInErrors: '1.3.6.1.2.1.2.2.1.14',
  rlifPresentOutErrors: '1.3.6.1.2.1.2.2.1.20'
};

/**
 * The per-port spanning-tree tables are indexed instance-by-port, so on a
 * switch with five VLANs and 424 bridge ports they hold over two thousand
 * rows across sixteen columns. A walk returns those column by column, so
 * any row limit truncates whole *columns* rather than trailing rows -- the
 * cap was being spent inside the index columns, every row came back
 * carrying an index and nothing else, and so every port looked disabled.
 *
 * Nothing is walked now. The VLANs (or instances) are already known, and
 * so are the bridge ports that map to real interfaces, so the exact
 * instances are fetched by name: a few hundred varbinds instead of tens of
 * thousands, and never a partial column.
 */
const PVST_PORT_COLUMNS = {
  rlBrgPvstOperPortPathCost: 4, rlBrgPvstOperPortPriority: 5,
  rlBrgPvstOperPortState: 6, rlBrgPvstOperPortRole: 7,
  rlBrgPvstOperPortEdgePort: 14, rlBrgPvstOperPortBpduSent: 15,
  rlBrgPvstOperPortBpduReceived: 16
};
const PVST_PORT_BASE = '1.3.6.1.4.1.9.6.1.101.57.9.4.1';

const MSTP_PORT_COLUMNS = {
  rldot1sMstpInstancePortPriority: 3, rldot1sMstpInstancePortState: 4,
  rldot1sMstpInstancePortPathCost: 6, rldot1sMstpInstancePortDesignatedBridge: 9,
  rldot1sMStpInstancePortRole: 13, rldot1sMStpInstancePortBpduSent: 14,
  rldot1sMStpInstancePortBpduReceived: 15
};
const MSTP_PORT_BASE = '1.3.6.1.4.1.9.6.1.101.57.6.2.1';

// Bound the work on a switch with very many VLANs; any shortfall is
// reported rather than silently dropped.
const MAX_PORT_INSTANCES = 1200;
const GET_BATCH = 40;

// Interface columns worth showing on a health page. The full table is 41
// columns wide; these are the ones that indicate a problem.
const IFACE_COLUMNS = [
  'rlifPresentName', 'rlifPresentDescr', 'rlifPresentAdminStatus',
  'rlifPresentOperStatus', 'rlifPresentHighSpeed', 'rlifPresentLastChange',
  'rlifPresentInErrors', 'rlifPresentOutErrors',
  'rlifPresentInDiscards', 'rlifPresentOutDiscards',
  'rlifPresentHCInOctets', 'rlifPresentHCOutOctets'
];

// PoE budget per model, from the Catalyst 1300 datasheet. Used to sanity
// check what the PSE table reports: a switch cannot have a smaller PoE
// budget than the model it is.
const MODEL_POE = {
  'C1300-8P-E-2G': { watts: 67, ports: 8 },
  'C1300-8FP-2G': { watts: 120, ports: 8 },
  'C1300-16P-2G': { watts: 120, ports: 16 },
  'C1300-16FP-2G': { watts: 240, ports: 16 },
  'C1300-24P-4G': { watts: 195, ports: 24 },
  'C1300-24FP-4G': { watts: 375, ports: 24 },
  'C1300-48P-4G': { watts: 375, ports: 48 },
  'C1300-48FP-4G': { watts: 740, ports: 48 },
  'C1300-16P-4X': { watts: 120, ports: 16 },
  'C1300-24P-4X': { watts: 195, ports: 24 },
  'C1300-24FP-4X': { watts: 375, ports: 24 },
  'C1300-48P-4X': { watts: 375, ports: 48 },
  'C1300-48FP-4X': { watts: 740, ports: 48 },
  'C1300-8MGP-2X': { watts: 120, ports: 8 },
  'C1300-24MGP-4X': { watts: 375, ports: 24 },
  'C1300-48MGP-4X': { watts: 740, ports: 48 }
};

// The smallest PoE budget any PoE-capable model in the range ships with.
// A PSE entry reporting less than this is not a real power source -- it is
// a phantom or placeholder row -- so it is excluded from totals and from
// alerting rather than being allowed to drag the reported budget down.
const MIN_REAL_PSE_WATTS = Math.min.apply(null, Object.values(MODEL_POE).map((m) => m.watts));

/** Pull a model number out of sysDescr / stack product id / inventory. */
function detectModel(strings) {
  for (const s of strings) {
    if (!s) continue;
    const m = String(s).toUpperCase().match(/C1300-[0-9]+[A-Z]*(?:-[A-Z])?-[0-9]*[A-Z]+/);
    if (m && MODEL_POE[m[0]]) return m[0];
  }
  for (const s of strings) {
    if (!s) continue;
    const m = String(s).toUpperCase().match(/C1300-[A-Z0-9-]+/);
    if (m) return m[0];
  }
  return null;
}

// Thresholds for the derived alerts. Deliberately conservative: this view
// should surface real problems, not cry wolf on a busy switch.
const THRESHOLDS = {
  cpuWarn: 80,          // % over 5 minutes
  flashFreeWarn: 10,    // % remaining
  tempWarn: 65,         // celsius
  tempCrit: 80,
  poeUsageWarn: 90      // % of budget
};

/**
 * Group walk results into rows keyed by instance index.
 *
 * `display` is dropped when it is just the stringified value, which is the
 * common case for counters and indexes. On a switch with a full forwarding
 * database that is thousands of duplicated strings on the wire for no gain;
 * readers fall back to `value` when `display` is absent.
 */
function pivot(results) {
  const rows = new Map();
  for (const r of results || []) {
    if (r.error || !r.column) continue;
    const idx = r.index === undefined ? '' : r.index;
    if (!rows.has(idx)) rows.set(idx, { index: idx });
    const cell = { value: r.value };
    if (r.display !== undefined && r.display !== String(r.value)) cell.display = r.display;
    rows.get(idx)[r.column] = cell;
  }
  return Array.from(rows.values());
}

const val = (row, col) => (row && row[col] ? row[col].value : undefined);
const disp = (row, col) => {
  const cell = row && row[col];
  if (!cell) return undefined;
  return cell.display !== undefined ? cell.display : String(cell.value);
};

/**
 * entPhySensorValue is a raw integer that has to be scaled: `precision`
 * gives the number of implied decimal places, so a precision of 1 and a
 * value of 425 means 42.5 degrees.
 */
function sensorValue(row) {
  const raw = Number(val(row, 'entPhySensorValue'));
  if (!Number.isFinite(raw)) return null;
  const precision = Number(val(row, 'entPhySensorPrecision')) || 0;
  return precision > 0 ? raw / Math.pow(10, precision) : raw;
}

/**
 * A PortList is a bit-per-port OCTET STRING: byte 0 bit 7 is port 1. It
 * arrives here either as readable text or as a hex dump, depending on
 * whether the bytes happened to be printable, so both forms are handled.
 */
function decodePortList(value) {
  if (value === undefined || value === null) return [];
  let bytes;
  const s = String(value).trim();
  if (/^([0-9a-f]{2}[\s:]*)+$/i.test(s) && s.replace(/[^0-9a-f]/gi, '').length % 2 === 0) {
    const hex = s.replace(/[^0-9a-f]/gi, '');
    bytes = [];
    for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
  } else {
    bytes = Array.from(s, (c) => c.charCodeAt(0) & 0xff);
  }
  const ports = [];
  bytes.forEach((b, i) => {
    for (let bit = 0; bit < 8; bit++) {
      if (b & (0x80 >> bit)) ports.push(i * 8 + bit + 1);
    }
  });
  return ports;
}

/** Collapse [1,2,3,7] into "1-3,7" so a 48-port list stays readable. */
function rangeText(nums) {
  if (!nums.length) return '';
  const out = [];
  let start = nums[0], prev = nums[0];
  for (let i = 1; i <= nums.length; i++) {
    const n = nums[i];
    if (n === prev + 1) { prev = n; continue; }
    out.push(start === prev ? String(start) : start + '-' + prev);
    start = prev = n;
  }
  return out.join(',');
}

/**
 * The discovery tables index themselves by things a human does not think
 * in: CDP by ifIndex, LLDP by timeMark.port.index, the FDB by bridge port
 * number. Resolve those to interface names using the tables already
 * collected, and decode VLAN membership bitmaps into port lists.
 */
/** Same rule as pivot(): no point sending a display string that is the value. */
function cell(value, display) {
  return display !== undefined && display !== String(value) ? { value, display } : { value };
}

/**
 * Which spanning-tree family is running?
 *
 * dot1dStpVersion is the obvious answer and the wrong one to trust on its
 * own: Catalyst 1200/1300 firmware happily reports `rstp` there while
 * actually running Rapid-PVST, and some builds do not implement the object
 * at all. Believing it meant the per-VLAN tables were never walked and the
 * page showed only the common instance -- which reports every port
 * disabled and is exactly the misleading view this panel exists to avoid.
 *
 * So the small per-instance tables are always walked and the decision is
 * made on evidence: if the switch is populating per-VLAN or per-instance
 * state, that is the family in use, whatever the scalar claims. The scalar
 * only breaks ties and names the plain STP/RSTP cases, where there is no
 * per-instance table to find.
 */
function stpFamily(h) {
  const version = (h.scalars.dot1dStpVersion && h.scalars.dot1dStpVersion.display) || '';
  const spec = (h.scalars.dot1dStpProtocolSpecification && h.scalars.dot1dStpProtocolSpecification.display) || '';
  const hasPvst = h.pvstVlans.length > 0;
  const hasMstp = h.mstpInstances.length > 0;

  let chosen;
  if (hasPvst && hasMstp) {
    // Both populated: let the reported version settle it.
    chosen = /mstp/i.test(version) ? 'mstp' : 'pvst';
  } else if (hasPvst) chosen = 'pvst';
  else if (hasMstp) chosen = 'mstp';
  else if (/rpvst|pvst/i.test(version)) chosen = 'pvst';
  else if (/mstp/i.test(version)) chosen = 'mstp';
  else if (/rstp/i.test(version)) chosen = 'rstp';
  else if (/stpCompatible/i.test(version)) chosen = 'stp';
  else if (/ieee8021d/i.test(spec)) chosen = 'stp';
  else chosen = 'unknown';

  // Keep the workings, so a switch that reports one thing and behaves like
  // another is diagnosable from the page instead of by guesswork.
  h.stpDetect = {
    reportedVersion: version || null,
    protocolSpecification: spec || null,
    pvstVlanRows: h.pvstVlans.length,
    mstpInstanceRows: h.mstpInstances.length,
    chosen,
    disagrees: !!((hasPvst && /mstp|rstp|stpCompatible/i.test(version)) ||
                  (hasMstp && /pvst/i.test(version)))
  };
  return chosen;
}

/**
 * A bridge ID is eight bytes: two of priority, six of MAC. Rendering it as
 * a hex dump is useless -- what an operator needs is the priority (to see
 * who wins the election) and the address (to recognise the device).
 */
function formatBridgeId(raw) {
  if (raw === undefined || raw === null) return undefined;
  const hex = String(raw).replace(/[^0-9a-f]/gi, '');
  if (hex.length < 16) return String(raw);
  const priority = parseInt(hex.slice(0, 4), 16);
  const mac = (hex.slice(4, 16).match(/../g) || []).join(':').toUpperCase();
  // The low 12 bits are the "system ID extension" (the VLAN or instance),
  // so report the configurable part separately from the raw value.
  const base = priority & 0xf000;
  const ext = priority & 0x0fff;
  return priority + (ext ? ' (' + base + ' + ' + ext + ')' : '') + '  ' + mac;
}

/**
 * BRIDGE-MIB timers are of type Timeout: hundredths of a second. Shown
 * raw they read as "max age 2,000", which looks like a cost and not like
 * the 20 seconds the CLI reports.
 */
function secondsFromTimeout(raw) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return undefined;
  const secs = n / 100;
  return (Number.isInteger(secs) ? secs : secs.toFixed(2)) + ' sec';
}

const TIMER_SCALARS = ['dot1dStpMaxAge', 'dot1dStpHelloTime', 'dot1dStpForwardDelay',
  'dot1dStpBridgeMaxAge', 'dot1dStpBridgeHelloTime', 'dot1dStpBridgeForwardDelay'];
// The vendor per-VLAN and per-instance timers are documented in *seconds*
// ("the operational maximum age time in seconds"), unlike the BRIDGE-MIB
// scalars above. Dividing them by 100 turned a 2-second hello into
// "0.02 sec"; they only need a unit appended.
const TIMER_COLUMNS_SECONDS = [
  'rlBrgPvstOperVlanMaxAge', 'rlBrgPvstOperVlanHelloTime', 'rlBrgPvstOperVlanForwardDelay',
  'rlBrgPvstOperVlanRootMaxAge', 'rlBrgPvstOperVlanRootHelloTime', 'rlBrgPvstOperVlanRootForwardDelay',
  'rldot1sMstpInstanceMaxAge', 'rldot1sMstpInstanceHelloTime', 'rldot1sMstpInstanceForwardDelay',
  'rldot1sMstpInstanceHoldTime'
];

function decorateDiscovered(h) {
  // ifOperStatus notPresent(6) means the interface is not physically
  // there: a slot the switch describes but has no hardware for. It is not
  // a down port, and listing it is noise wherever the list came from.
  const notPresent = (row) => {
    const cell = row.rlifPresentOperStatus;
    if (!cell) return false;
    const text = String(cell.display !== undefined ? cell.display : cell.value);
    return /notpresent/i.test(text) || text.trim() === '6' || /\(6\)/.test(text);
  };
  const before = h.interfaces.length;
  h.interfaces = h.interfaces.filter((r) => !notPresent(r));
  if (h.interfaces.length !== before) {
    h.interfacesNotPresent = before - h.interfaces.length;
  }

  const ifName = new Map();
  for (const row of h.interfaces) {
    const n = val(row, 'rlifPresentName') || val(row, 'rlifPresentDescr');
    if (n) ifName.set(String(row.index), String(n));
  }
  const bridgeToIf = new Map();
  for (const row of h.bridgePorts) {
    const ifx = val(row, 'dot1dBasePortIfIndex');
    if (ifx !== undefined) bridgeToIf.set(String(row.index), String(ifx));
  }
  const portLabel = (ifIndex) => ifName.get(String(ifIndex)) || ('ifIndex ' + ifIndex);

  // CDP is indexed ifIndex.deviceIndex
  for (const row of h.cdp) {
    const local = String(row.index).split('.')[0];
    row.localPort = cell(local, portLabel(local));
  }
  // LLDP is indexed timeMark.localPortNum.index
  for (const row of h.lldp) {
    const parts = String(row.index).split('.');
    const local = parts.length >= 2 ? parts[1] : parts[0];
    row.localPort = cell(local, portLabel(local));
  }
  // FDB is indexed vlan.mac, and its port column is a bridge port number
  for (const row of h.macTable) {
    const parts = String(row.index).split('.');
    row.vlan = cell(parts[0], parts[0]);
    // The address is the last six sub-identifiers: some agents prefix a
    // length byte for the OCTET STRING, most do not, and taking the tail
    // is correct either way.
    if (parts.length >= 7) {
      const mac = parts.slice(-6).map((x) => Number(x).toString(16).padStart(2, '0')).join(':').toUpperCase();
      if (mac.length === 17) row.mac = cell(mac, mac);
    }
    const bp = val(row, 'dot1qTpFdbPort');
    if (bp !== undefined) {
      const ifx = bridgeToIf.get(String(bp));
      row.port = cell(bp, ifx ? portLabel(ifx) : ('bridge port ' + bp));
    }
  }
  // ---- VLANs ----
  // Membership comes from dot1qVlanCurrentTable, which is the operational
  // view and is populated even when the static table is not. The static
  // table is only consulted for names. Current rows are indexed
  // timeMark.vlanId, so the id is the second component.
  const staticByVlan = new Map();
  for (const row of h.vlans) staticByVlan.set(String(row.index), row);

  const portNames = (ports) => ports.map((n) => ifName.get(String(n)) || String(n));
  const merged = [];
  const seen = new Set();

  // Per-port CONFIGURED VLAN -> set of ifIndexes, used to fold in the membership
  // of ports whose VLAN was set while operationally down (the static egress
  // bitmap omits those). Strict guards, because the per-port access/native VLAN
  // tables carry a row for EVERY port - including ports not in that mode and
  // phantom indexes not present on the switch - all defaulting to VLAN 1:
  //   - only REAL ports (present in the interface table / ifName), and
  //   - access VLAN only when the port is in ACCESS mode, native VLAN only when
  //     in TRUNK mode (from vlanPortModeState: 11 = access, 12 = trunk).
  const cvNum = (row, col) => { const c = row[col]; const v = c && (c.value !== undefined ? c.value : c.display); const n = parseInt(v, 10); return Number.isFinite(n) ? n : null; };
  const portModeByIf = new Map();   // ifIndex -> 11 (access) | 12 (trunk)
  for (const row of (h.portModes || [])) { const m = cvNum(row, 'vlanPortModeState'); if (m != null) portModeByIf.set(String(row.index), m); }
  const configuredByVlan = new Map();   // vlanId(str) -> Set(ifIndex str)
  const addCfg = (vlanId, ifx, wantMode) => {
    if (vlanId == null || vlanId <= 0) return;
    const key = String(ifx);
    if (!ifName.has(key)) return;                       // skip phantom/non-existent ports
    if (portModeByIf.get(key) !== wantMode) return;     // only the matching switchport mode
    const k = String(vlanId);
    if (!configuredByVlan.has(k)) configuredByVlan.set(k, new Set());
    configuredByVlan.get(k).add(key);
  };
  for (const row of (h.portAccessVlan || [])) addCfg(cvNum(row, 'vlanAccessPortModeVlanId'), row.index, 11);
  for (const row of (h.portNativeVlan || [])) addCfg(cvNum(row, 'vlanTrunkPortModeNativeVlanId'), row.index, 12);

  // Natural sort by interface name so gi1/0/2 comes before gi1/0/10 and before
  // te/tw ports, rather than lexical order.
  const nameSort = (a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });

  // Compress a list of interface names into type-grouped ranges, e.g.
  // gi1/0/1, gi1/0/4..16, tw1/0/17..22, te1/0/1..4, Po1 ->
  // "gi1/0/1, gi1/0/4-16, tw1/0/17-22, te1/0/1-4, Po1". Ordered by port type
  // (gigabit, two-gig, ten-gig, port-channel) then path, with consecutive port
  // numbers collapsed into N-M ranges.
  const PORT_TYPE_ORDER = { gi: 0, tw: 1, te: 2, fo: 3, hu: 4, po: 9 };
  const compressPortNames = (names) => {
    const parsed = names.map((nm) => {
      const m = String(nm).match(/^([a-zA-Z]+)(.*?)(\d+)$/);
      return m ? { type: m[1].toLowerCase(), path: m[2], num: parseInt(m[3], 10), raw: nm } : { type: 'zzz', path: '', num: 0, raw: nm };
    });
    const ord = (t) => (PORT_TYPE_ORDER[t] !== undefined ? PORT_TYPE_ORDER[t] : 50);
    const groups = new Map();
    for (const p of parsed) { const k = p.type + '|' + p.path; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(p); }
    const keys = Array.from(groups.keys()).sort((a, b) => {
      const ga = groups.get(a)[0], gb = groups.get(b)[0];
      return ord(ga.type) - ord(gb.type) || ga.path.localeCompare(gb.path, undefined, { numeric: true }) || ga.type.localeCompare(gb.type);
    });
    const out = [];
    for (const k of keys) {
      const items = groups.get(k).sort((a, b) => a.num - b.num);
      const prefix = items[0].raw.slice(0, items[0].raw.length - String(items[0].num).length);
      let i = 0;
      while (i < items.length) {
        let j = i;
        while (j + 1 < items.length && items[j + 1].num === items[j].num + 1) j++;
        out.push(j === i ? items[i].raw : (prefix + items[i].num + '-' + items[j].num));
        i = j + 1;
      }
    }
    return out;
  };

  const buildVlan = (vlanId, egressRaw, untaggedRaw, nameRow) => {
    const eg = decodePortList(egressRaw);
    const un = decodePortList(untaggedRaw);
    const unSet = new Set(un);
    const taggedBp = eg.filter((n) => !unSet.has(n));
    const nameCell = nameRow && nameRow.dot1qVlanStaticName;
    const name = nameCell ? (nameCell.display !== undefined ? nameCell.display : nameCell.value) : '';

    // Work entirely in ifIndex space and render by interface NAME, so there is
    // one consistent representation (no bridge-number vs name duplication). Map
    // the static egress/untagged bridge ports to ifIndexes, then fold in the
    // per-port CONFIGURED members (ports whose VLAN was set while down, which
    // the egress bitmap omits) as untagged.
    const bpToIfx = (bp) => bridgeToIf.get(String(bp)) || String(bp);
    const unIfx = new Set(un.map(bpToIfx));
    const tagIfx = new Set(taggedBp.map(bpToIfx));
    const configured = configuredByVlan.get(String(vlanId)) || new Set();
    for (const ifx of configured) { if (!unIfx.has(String(ifx)) && !tagIfx.has(String(ifx))) unIfx.add(String(ifx)); }
    // De-dup across the two lists (a port is untagged OR tagged, not both).
    for (const ifx of unIfx) tagIfx.delete(ifx);

    const unNames = compressPortNames(Array.from(unIfx).map((ifx) => portLabel(ifx)).sort(nameSort));
    const tagNames = compressPortNames(Array.from(tagIfx).map((ifx) => portLabel(ifx)).sort(nameSort));
    const memberCount = unIfx.size + tagIfx.size;

    return {
      index: String(vlanId),
      name: cell(name && name !== '(empty)' ? name : '', name && name !== '(empty)' ? name : '(unnamed)'),
      untagged: cell(Array.from(unIfx).join(','), unNames.join(', ') || '(none)'),
      tagged: cell(Array.from(tagIfx).join(','), tagNames.join(', ') || '(none)'),
      untaggedNames: cell(unNames.join(', ') || '(none)'),
      taggedNames: cell(tagNames.join(', ') || '(none)'),
      memberCount: cell(memberCount)
    };
  };

  for (const row of h.vlansCurrent) {
    const parts = String(row.index).split('.');
    const vlanId = parts.length > 1 ? parts[1] : parts[0];
    if (seen.has(vlanId)) continue;
    seen.add(vlanId);
    merged.push(buildVlan(vlanId,
      val(row, 'dot1qVlanCurrentEgressPorts'),
      val(row, 'dot1qVlanCurrentUntaggedPorts'),
      staticByVlan.get(vlanId)));
  }
  // Anything defined but not currently operational still deserves a row.
  for (const row of h.vlans) {
    if (seen.has(String(row.index))) continue;
    merged.push(buildVlan(row.index,
      val(row, 'dot1qVlanStaticEgressPorts'),
      val(row, 'dot1qVlanStaticUntaggedPorts'),
      row));
  }
  merged.sort((a, b) => Number(a.index) - Number(b.index));
  h.vlans = merged;

  // ---- authentication ----
  // 802.1x rows are indexed by port, and the multi-session table by
  // port.MAC, so both get the same interface name the rest of the page
  // uses, and the MAC gets the usual formatting.
  const macFromIndex = (parts) => parts.slice(-6).map((n) => {
    const hex = Number(n).toString(16).toUpperCase();
    return hex.length < 2 ? '0' + hex : hex;
  }).join(':');

  for (const row of h.dot1xHosts) {
    const parts = String(row.index).split('.');
    if (parts.length >= 7) {
      row.port = cell(parts[0], portLabel(parts[0]));
      row.mac = cell(macFromIndex(parts));
    } else {
      row.port = cell(parts[0], portLabel(parts[0]));
    }
  }
  for (const row of h.dot1xLocked) {
    const parts = String(row.index).split('.');
    row.port = cell(parts[0], portLabel(parts[0]));
    if (parts.length >= 7) row.mac = cell(macFromIndex(parts));
  }

  // ---- spanning tree ----
  // The STP tables are indexed by bridge port, like the forwarding
  // database, so the same mapping turns them into interface names.
  const bridgeLabel = (bp) => {
    const ifx = bridgeToIf.get(String(bp));
    if (ifx) return portLabel(ifx);
    // Without dot1dBasePortTable the bridge port number is the ifIndex on
    // these switches, so the name is still recoverable.
    if (ifName.has(String(bp))) return portLabel(bp);
    return 'bridge port ' + bp;
  };
  // Did a bridge port resolve to an interface the switch actually has?
  // Anything that did not is a slot in the ifIndex space rather than a
  // port, and has no business in a per-VLAN table.
  const resolvesToInterface = (bp) => {
    if (!ifName.size) return true;   // no interface list: cannot tell, so keep it
    const ifx = bridgeToIf.get(String(bp));
    if (ifx) return ifName.has(String(ifx));
    return ifName.has(String(bp));   // switches that map bridge port 1:1 to ifIndex
  };

  // Switches report a bridge port for every slot in their ifIndex space,
  // including stack members that are not fitted and LAGs that do not
  // exist. A 24-port switch answering for 424 ports buries the handful
  // that matter, so rows are kept only for interfaces that are actually
  // present -- the same reasoning behind using rlifPresentTable instead of
  // ifTable everywhere else.
  const isRealPort = (bp) => {
    if (!ifName.size) return true;              // cannot tell; keep everything
    const ifx = bridgeToIf.get(String(bp));
    if (ifx) return ifName.has(String(ifx));
    // No mapping table: the bridge port number is the ifIndex here, so the
    // interface list is still enough to tell a real port from a slot.
    return ifName.has(String(bp));
  };
  // A row with no state and no role carries nothing, whatever the port is.
  const hasSubstance = (row, cols) => cols.some((c) => val(row, c) !== undefined);

  const prune = (rows, portOf, cols) => {
    const kept = [];
    let omitted = 0;
    for (const row of rows) {
      if (isRealPort(portOf(row)) && hasSubstance(row, cols)) kept.push(row);
      else omitted++;
    }
    return { kept, omitted };
  };
  // pethPsePortTable is indexed group.port; the port half is the ifIndex
  // on these switches, which is what lets PoE be shown alongside the
  // interface it belongs to rather than in a table of its own.
  for (const row of h.poePorts) {
    const parts = String(row.index).split('.');
    const portNum = parts.length > 1 ? parts[1] : parts[0];
    row.portIndex = portNum;
    row.port = cell(portNum, portLabel(portNum));
  }

  const extByPort = new Map();
  for (const row of h.stpExtPorts) extByPort.set(String(row.index), row);

  const prunedStp = prune(h.stpPorts, (r) => r.index,
    ['dot1dStpPortState', 'dot1dStpPortEnable', 'dot1dStpPortPathCost']);
  h.stpPorts = prunedStp.kept;
  h.stpPortsOmitted = prunedStp.omitted;

  for (const row of h.stpPorts) {
    row.port = cell(row.index, bridgeLabel(row.index));
    row.realPort = resolvesToInterface(row.index);
    for (const col of ['dot1dStpPortDesignatedRoot', 'dot1dStpPortDesignatedBridge']) {
      const raw = val(row, col);
      if (raw !== undefined) row[col] = cell(raw, formatBridgeId(raw));
    }
    const ext = extByPort.get(String(row.index));
    if (ext) {
      row.edge = ext.dot1dStpPortOperEdgePort;
      row.p2p = ext.dot1dStpPortOperPointToPoint;
    }
  }

  for (const col of ['dot1dStpDesignatedRoot', 'dot1dBaseBridgeAddress']) {
    const sc = h.scalars[col];
    if (sc) {
      const pretty = col === 'dot1dStpDesignatedRoot'
        ? formatBridgeId(sc.value)
        : String(sc.display || sc.value);
      if (pretty) sc.display = pretty;
    }
  }
  for (const key of TIMER_SCALARS) {
    const sc = h.scalars[key];
    if (!sc) continue;
    const pretty = secondsFromTimeout(sc.value);
    if (pretty) sc.display = pretty;
  }
  for (const list of [h.pvstVlans, h.mstpInstances]) {
    for (const row of list) {
      for (const col of TIMER_COLUMNS_SECONDS) {
        if (!row[col]) continue;
        const n = Number(row[col].value);
        if (Number.isFinite(n)) row[col] = { value: n, display: n + ' sec' };
      }
    }
  }

  const rootPort = h.scalars.dot1dStpRootPort;
  if (rootPort && Number(rootPort.value) > 0) rootPort.display = bridgeLabel(rootPort.value);
  else if (rootPort) rootPort.display = 'none (this switch is the root)';


  for (const row of h.mstpPorts) {
    // Indexed instance.port
    const parts = String(row.index).split('.');
    row.instance = cell(parts[0]);
    row.port = cell(parts[1], bridgeLabel(parts[1]));
    row.realPort = resolvesToInterface(parts[1]);
    for (const col of ['rldot1sMstpInstancePortDesignatedRoot', 'rldot1sMstpInstancePortDesignatedBridge']) {
      const raw = val(row, col);
      if (raw !== undefined) row[col] = cell(raw, formatBridgeId(raw));
    }
  }
  // Is a given instance rooted on this switch? The CLI answers this
  // outright ("This switch is the root"); over SNMP it has to be derived
  // by comparing the designated root's address with our own bridge
  // address, which is the same comparison the switch makes.
  const ourMac = String((h.scalars.dot1dBaseBridgeAddress &&
    (h.scalars.dot1dBaseBridgeAddress.display || h.scalars.dot1dBaseBridgeAddress.value)) || '').toUpperCase();
  const rootedHere = (raw) => {
    if (!ourMac || raw === undefined) return false;
    const formatted = String(formatBridgeId(raw) || '').toUpperCase();
    return formatted.indexOf(ourMac) >= 0;
  };

  for (const row of h.mstpInstances) {
    const raw = val(row, 'rldot1sMstpInstanceDesignatedRoot');
    if (raw !== undefined) {
      row.isRoot = cell(rootedHere(raw) ? 1 : 0, rootedHere(raw) ? 'yes' : 'no');
      row.rldot1sMstpInstanceDesignatedRoot = cell(raw, formatBridgeId(raw));
    }
    const rp = val(row, 'rldot1sMstpInstanceRootPort');
    if (rp !== undefined) {
      row.rootPort = cell(rp, Number(rp) > 0 ? bridgeLabel(rp) : '\u2014');
    }
  }

  for (const row of h.pvstPorts) {
    const parts = String(row.index).split('.');
    row.vlan = cell(parts[0]);
    row.port = cell(parts[1], bridgeLabel(parts[1]));
    row.realPort = resolvesToInterface(parts[1]);
    for (const col of ['rlBrgPvstOperPortDesignatedRoot', 'rlBrgPvstOperPortDesignatedBridge']) {
      const raw = val(row, col);
      if (raw !== undefined) row[col] = cell(raw, formatBridgeId(raw));
    }
  }
  for (const row of h.pvstVlans) {
    const raw = val(row, 'rlBrgPvstOperVlanDesignatedRoot');
    if (raw !== undefined) {
      row.isRoot = cell(rootedHere(raw) ? 1 : 0, rootedHere(raw) ? 'yes' : 'no');
      row.rlBrgPvstOperVlanDesignatedRoot = cell(raw, formatBridgeId(raw));
    }
    const rp = val(row, 'rlBrgPvstOperVlanRootPort');
    if (rp !== undefined) {
      row.rootPort = cell(rp, Number(rp) > 0 ? bridgeLabel(rp) : '\u2014');
    }
  }
  for (const row of h.pvstInconsistencies) {
    const bp = val(row, 'rlBrgPvstInconsistencyPort');
    if (bp !== undefined) row.port = cell(bp, bridgeLabel(bp));
    else {
      // Indexed vlan.port when the port column is not accessible.
      const parts = String(row.index).split('.');
      if (parts.length >= 2) {
        row.vlan = cell(parts[0]);
        row.port = cell(parts[1], bridgeLabel(parts[1]));
      }
    }
    if (!row.vlan) {
      const v = val(row, 'rlBrgPvstInconsistencyVlanId');
      if (v !== undefined) row.vlan = cell(v);
    }
    row.state = row.rlBrgPvstInconsistencyState;
  }
  // The standard Cisco table is indexed vlan.port and carries the state in
  // stpxInconsistentState; normalise it into the same shape.
  for (const row of h.stpxInconsistencies) {
    const parts = String(row.index).split('.');
    const entry = {
      index: row.index,
      vlan: cell(parts[0]),
      port: cell(parts[1], bridgeLabel(parts[1])),
      state: row.stpxInconsistentState
    };
    h.pvstInconsistencies.push(entry);
  }
}

/** 4812 -> "4,812" */
function groupDigits(n) {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function buildAlerts(h) {
  const alerts = [];
  const add = (severity, area, message) => alerts.push({ severity, area, message });

  // Front-panel LED is the switch's own summary of its health.
  const led = h.scalars.rlEnvSystemLed;
  if (led && /amber/i.test(led.display || '')) {
    add('critical', 'System', 'Front-panel status LED is amber - the switch is reporting a fault.');
  }

  const cpu5 = Number(h.scalars.rlCpuUtilDuringLast5Minutes && h.scalars.rlCpuUtilDuringLast5Minutes.value);
  if (Number.isFinite(cpu5) && cpu5 >= THRESHOLDS.cpuWarn) {
    add('warning', 'CPU', `CPU at ${cpu5}% averaged over 5 minutes.`);
  }

  const total = Number(h.scalars.rlFileTotalSizeOfFlash && h.scalars.rlFileTotalSizeOfFlash.value);
  const free = Number(h.scalars.rlFileFreeSizeOfFlash && h.scalars.rlFileFreeSizeOfFlash.value);
  if (Number.isFinite(total) && Number.isFinite(free) && total > 0) {
    const pct = (free / total) * 100;
    if (pct < THRESHOLDS.flashFreeWarn) {
      add('warning', 'Flash', `Only ${pct.toFixed(1)}% of flash remains free.`);
    }
  }

  const cfg = h.scalars.rlRunningCDBequalToStartupCDB;
  if (cfg && /false|no\b|notEqual/i.test(cfg.display || '')) {
    add('warning', 'Config', 'Running configuration differs from startup - changes will be lost on reload.');
  }

  for (const p of h.psus) {
    const state = disp(p, 'rlEnvMonSupplyState') || '';
    const name = val(p, 'rlEnvMonSupplyStatusDescr') || `PSU ${p.index}`;
    if (/notPresent/i.test(state)) continue;               // an empty bay is normal
    if (!/normal/i.test(state)) {
      add(/critical|shutdown|notFunctioning/i.test(state) ? 'critical' : 'warning',
        'Power', `${name}: ${state}`);
    }
  }

  for (const f of h.fans) {
    const state = disp(f, 'rlEnvMonFanState') || '';
    const name = val(f, 'rlEnvMonFanStatusDescr') || `Fan ${f.index}`;
    if (/notPresent|notAvailable/i.test(state)) continue;
    if (!/normal/i.test(state)) {
      add(/critical|shutdown|notFunctioning/i.test(state) ? 'critical' : 'warning',
        'Cooling', `${name}: ${state}`);
    }
  }

  for (const s of h.sensors) {
    const type = disp(s, 'entPhySensorType') || '';
    if (!/celsius/i.test(type)) continue;
    const v = sensorValue(s);
    if (v == null) continue;
    if (v >= THRESHOLDS.tempCrit) add('critical', 'Temperature', `Sensor ${s.index} at ${v}\u00b0C.`);
    else if (v >= THRESHOLDS.tempWarn) add('warning', 'Temperature', `Sensor ${s.index} at ${v}\u00b0C.`);
  }

  // Per-port PoE faults. pethPsePortDetectionStatus reports fault(4) and
  // otherFault(6) independently of whether anything is plugged in. A fault
  // on an empty port is still raised -- often a damaged PSE channel or a
  // wiring problem that will bite the moment a powered device is connected.
  //
  // What is NOT raised is a fault on a port whose link is up while the PSE
  // is not powering it: the device on the other end has its own power and
  // is not a PD (a PC, a server, another switch), so it never asked for PoE
  // and the fault says nothing about it. A PD that the PSE failed to power
  // has no power to bring its link up with, so it still alerts. Seen on a
  // C1300-24MGP-4X: gi1/0/3 linked up to a non-PD reported fault (4), "Port
  // is off. Short condition", with rlPethPsePortLinkPartnerPoeType none(1);
  // the two powered phones beside it reported poe(2). The link state needs no
  // extra walk, so that is what decides here. The PoE row's
  // port half is the ifIndex (decorateDiscovered sets portIndex), which is
  // how the port's link state is found.
  const linkUp = new Set();
  for (const i of (h.interfaces || [])) {
    if (/^up/i.test(disp(i, 'rlifPresentOperStatus') || '')) linkUp.add(String(i.index));
  }
  const poeFaults = [];
  for (const port of h.poePorts) {
    const status = disp(port, 'pethPsePortDetectionStatus') || '';
    const portIf = String(port.portIndex != null ? port.portIndex : String(port.index).split('.').pop());
    if (/fault/i.test(status) && !linkUp.has(portIf)) {
      poeFaults.push({ port: port.index, status });
    }
    const denied = Number(val(port, 'pethPsePortPowerDeniedCounter'));
    if (Number.isFinite(denied) && denied > 0) {
      add('warning', 'PoE',
        `Port ${port.index} has denied power ${denied} time(s) - the port asked for more than the budget allowed.`);
    }
  }
  for (const f of poeFaults) {
    add('critical', 'PoE',
      `Port ${f.port} PoE detection reports ${f.status}. The port has no link, so this is a port-side fault.`);
  }

  for (const p of h.poe) {
    const budget = Number(val(p, 'pethMainPsePower'));
    const used = Number(val(p, 'pethMainPseConsumptionPower'));
    const status = disp(p, 'pethMainPseOperStatus') || '';
    if (/faulty/i.test(status)) add('critical', 'PoE', `PSE ${p.index} reports faulty.`);
    if (Number.isFinite(budget) && Number.isFinite(used) && budget > 0) {
      const pct = (used / budget) * 100;
      if (pct >= THRESHOLDS.poeUsageWarn) {
        add('warning', 'PoE', `PSE ${p.index} drawing ${used}W of ${budget}W (${pct.toFixed(0)}%).`);
      }
    }
  }

  // ---- authentication ----
  // A client the switch has locked out is a person who cannot work, or a
  // device quietly off the network; either way it wants noticing.
  if (h.dot1xLocked.length) {
    add('warning', '802.1x',
      h.dot1xLocked.length + ' client(s) are locked out after failed authentication: ' +
      h.dot1xLocked.map((r) => (disp(r, 'mac') || '?') + ' on ' + (disp(r, 'port') || '?'))
        .slice(0, 5).join(', '));
  }

  // ---- spanning tree ----
  // A stable topology is silent. Churn, a port stuck out of forwarding, or
  // an inconsistency are the things worth surfacing.
  const since = Number(h.scalars.dot1dStpTimeSinceTopologyChange &&
    h.scalars.dot1dStpTimeSinceTopologyChange.value);
  const changes = Number(h.scalars.dot1dStpTopChanges && h.scalars.dot1dStpTopChanges.value);
  if (Number.isFinite(since) && Number.isFinite(changes) && changes > 0) {
    const seconds = since / 100;   // TimeTicks
    if (seconds < 300) {
      add('warning', 'Spanning tree',
        `Topology changed ${Math.round(seconds)}s ago (${changes} change(s) since boot). ` +
        'Frequent changes mean a link is flapping or a device is joining and leaving.');
    }
  }
  const broken = h.stpPorts.filter((p) => /broken/i.test(disp(p, 'dot1dStpPortState') || ''));
  if (broken.length) {
    add('critical', 'Spanning tree',
      broken.length + ' port(s) report the spanning-tree state "broken": ' +
      broken.map((p) => disp(p, 'port')).join(', '));
  }
  if (h.pvstInconsistencies.length) {
    add('critical', 'Spanning tree',
      h.pvstInconsistencies.length + ' port/VLAN pair(s) are blocked for a spanning-tree ' +
      'inconsistency: ' + h.pvstInconsistencies.map((r) =>
        disp(r, 'port') + ' VLAN ' + (disp(r, 'vlan') || '?') +
        (disp(r, 'state') ? ' (' + disp(r, 'state') + ')' : '')).slice(0, 6).join(', '));
  }
  // Being the root bridge is a fact about the topology, not a problem, and
  // it is already stated on the spanning-tree panel. Findings are for
  // things that want doing something about, so it is not one.

  /**
   * Interface errors, as a rate.
   *
   * A counter is cumulative since boot, so on a switch that has been up
   * for months a non-zero total is close to guaranteed and says nothing
   * about now -- it could be a cable failing this minute or one bad hour
   * last March. What matters is whether it is still climbing.
   *
   * With a previous collection to compare against, only interfaces whose
   * counters have moved are reported, with how fast. Without one -- the
   * first collection after a restart -- the totals are reported instead,
   * and labelled as totals so they are not mistaken for a rate.
   */
  const rising = [];
  for (const i of h.interfaces) {
    const now = ['rlifPresentInErrors', 'rlifPresentOutErrors']
      .reduce((a, c) => a + (Number(val(i, c)) || 0), 0);
    if (!now) continue;
    const name = val(i, 'rlifPresentName') || i.index;
    const was = h.previousErrors && h.previousErrors.get(String(i.index));
    if (was === undefined || was === null) continue;   // no baseline yet: wait for the next poll
    const delta = now - was;
    // A counter that wrapped or was cleared reads negative; not a fault.
    if (delta > 0) rising.push({ name, delta });
  }

  if (rising.length) {
    const per = h.previousElapsedMs ? Math.max(1, Math.round(h.previousElapsedMs / 1000)) : null;
    rising.sort((a, b) => b.delta - a.delta);
    add('warning', 'Interfaces',
      `Error counters still rising on ${rising.length} interface(s)` +
      (per ? ` in the last ${per}s` : '') + ': ' +
      rising.slice(0, 8).map((r) => `${r.name} (+${groupDigits(r.delta)})`).join(', ') +
      (rising.length > 8 ? ' \u2026' : ''));
  }
  // The former "carry error counters from earlier" info notice is intentionally
  // NOT raised as a finding: cumulative counters are non-zero on any switch
  // that has been up a while, it is not a problem, and as a standing finding it
  // lingered on screen until the next full poll. Only ERRORS STILL RISING (the
  // actionable case, above) is surfaced; a static total is just history.

  if (!alerts.length) add('ok', 'System', 'No problems detected in the polled health data.');
  return alerts;
}

/**
 * Collect everything. `get` and `walk` are promise-returning helpers
 * supplied by the server so this module stays transport-agnostic.
 */
/**
 * Tables that have to come along for a partial collection to make sense:
 * the discovery tables index themselves by ifIndex and bridge port, and
 * without these the rows would show numbers where names belong.
 */
const DECORATION_DEPS = {
  cdp: ['interfaces'],
  lldp: ['interfaces'],
  vlans: ['interfaces', 'vlansCurrent'],
  vlansCurrent: ['interfaces', 'vlans'],
  macTable: ['interfaces', 'bridgePorts'],
  stpPorts: ['interfaces', 'bridgePorts', 'stpExtPorts'],
  mstpPorts: ['interfaces', 'bridgePorts'],
  pvstPorts: ['interfaces', 'bridgePorts']
};

/**
 * Collect everything, or -- when `only` is given -- just those tables.
 * A partial collection skips the scalars and the findings, because both
 * describe the whole switch and would be wrong if derived from a slice.
 */
async function collect({ get, walk, only, previous, reuse }) {
  const health = {
    collectedAt: new Date().toISOString(),
    scalars: {},
    failed: [],
    psus: [], fans: [], fanData: [], sensors: [], stack: [], poe: [], poePorts: [],
    interfaces: [], inventory: [], vlans: [], vlansCurrent: [], cdp: [], lldp: [],
    macTable: [], bridgePorts: [], stpPorts: [], stpExtPorts: [],
    mgmtSessions: [], sshSessions: [], telnetSessions: [],
    dot1xHosts: [], dot1xLocked: [],
    stpPortsOmitted: 0, mstpPortsOmitted: 0, pvstPortsOmitted: 0,
    mstpInstances: [], mstpPorts: [], pvstVlans: [], pvstPorts: [],
    pvstInconsistencies: [], stpxInconsistencies: []
  };

  /**
   * Fetch one table, by columns where they are named. The column walks run
   * one after another: they are already narrow, and firing them all at
   * once would just move the load onto the switch we are measuring.
   */
  const fetchTable = async (spec) => {
    // Raw mode: return the un-pivoted walk results ({ index, column, value,
    // display, oid }) instead of per-index rows. For a panel that joins several
    // subtrees itself by reading rows column-by-column (ACL: name+ACE+tuple with
    // pointer indirection) - it consumes exactly this shape, so the join logic
    // stays untouched while the data now rides the health cycle. spec.oids is a
    // list of subtree OIDs to walk and concatenate; spec.oid is the single-OID
    // form.
    if (spec.raw) {
      const oids = spec.oids || [spec.oid];
      // `raw` here means "do not pivot". The shared walk has its own `raw`
      // option (bare varbinds with no index or column), so it must not be
      // passed through, or every row loses the index and column the panel
      // joins on and the tables read as empty.
      const walkOpts = Object.assign({}, spec);
      delete walkOpts.raw;
      const out = [];
      for (const oid of oids) {
        try { for (const r of await walk(oid, walkOpts)) out.push(r); }
        catch (e) { /* a subtree this model lacks is not a failed table */ }
      }
      return out;
    }
    if (!spec.columns || !spec.columns.length) return pivot(await walk(spec.oid, spec));
    // The named columns are walked together (one GETBULK stream carries them
    // all); a column this model does not implement simply ends at once.
    try {
      return pivot(await walk(spec.columns, spec));
    } catch (e) {
      // No column answered: not a failed table, as before.
      return [];
    }
  };

  /**
   * Fetch a per-port table's named columns for exactly these ports, by GET,
   * in batches of GET_BATCH. Ports the switch does not know come back as
   * noSuchInstance and are dropped by pivot. If nothing at all answers (the
   * table is indexed some other way on this model, or not there), fall back
   * to walking it, so a model that differs only costs the old walk.
   */
  const fetchPorts = async (spec, ports) => {
    if (!ports || !ports.length || !spec.columns || !spec.columns.length) return fetchTable(spec);
    const oids = [];
    for (const column of spec.columns) for (const port of ports) oids.push(column + '.' + port);
    const results = [];
    for (let i = 0; i < oids.length; i += GET_BATCH) {
      try {
        for (const r of await get(oids.slice(i, i + GET_BATCH))) results.push(r);
      } catch (e) { /* one lost batch must not lose the rest */ }
    }
    const rows = pivot(results);
    return rows.length ? rows : fetchTable(spec);
  };

  // Bridge ports for the given interfaces. On these switches the bridge port
  // number IS the ifIndex, so dot1dBasePortIfIndex.<ifIndex> is read for each
  // interface and kept when it maps back to itself. If any answer maps
  // elsewhere, or none answers, the whole table is walked (the old way) and
  // its mapping is used instead. Returns the bridge ports whose interface
  // exists; sets health.bridgePorts.
  const resolveBridgePorts = async (present) => {
    const spec = TABLE_WALKS.bridgePorts;
    let rows = await fetchPorts(spec, present);
    const identity = rows.length > 0 &&
      rows.every((r) => String(val(r, 'dot1dBasePortIfIndex')) === String(r.index));
    if (!identity) rows = await fetchTable(spec);
    health.bridgePorts = rows;
    const exists = new Set(present.map(String));
    return rows.filter((r) => exists.has(String(val(r, 'dot1dBasePortIfIndex')))).map((r) => String(r.index));
  };

  // One table, by the cheapest read that gives the same rows.
  const carried = [];
  let present = [];        // ifIndexes of the interfaces that exist
  let bridgeList = null;   // bridge ports of those interfaces, once resolved
  const readTable = async (key, spec) => {
    if (spec.settings && reuse && Array.isArray(reuse[key])) {
      carried.push(key);
      return reuse[key];
    }
    if (spec.perPort === 'ifIndex' && present.length) return fetchPorts(spec, present);
    if (spec.perPort === 'bridgePort' && present.length) {
      if (!bridgeList) bridgeList = await resolveBridgePorts(present);
      if (bridgeList.length) return fetchPorts(spec, bridgeList);
    }
    return fetchTable(spec);
  };
  const indexesOf = (rows) => (rows || []).map((r) => String(r.index)).filter((i) => i !== '');

  const partial = Array.isArray(only) && only.length > 0;
  if (partial) {
    // Pull in whatever the requested tables need to be readable.
    const wanted = new Set(only);
    for (const key of only) for (const dep of DECORATION_DEPS[key] || []) wanted.add(dep);
    // Mode-specific tables are not in TABLE_WALKS, so include them when a
    // panel asks for them by name.
    const catalogue = Object.assign({}, TABLE_WALKS, MODE_WALKS.mstp, MODE_WALKS.pvst);
    const jobs = Object.entries(catalogue).filter(([key]) => wanted.has(key));
    // The interfaces that exist decide which rows a per-port table needs:
    // from this refresh when it reads interfaces (read first), otherwise from
    // the last full collection, otherwise one cheap column walk for the list.
    const needsPorts = jobs.some(([, spec]) => spec.perPort);
    if (needsPorts) {
      if (wanted.has('interfaces')) {
        try { health.interfaces = await fetchTable(TABLE_WALKS.interfaces); }
        catch (e) { health.failed.push({ what: TABLE_WALKS.interfaces.oid, error: e.message }); }
        present = indexesOf(health.interfaces);
      } else if (previous && Array.isArray(previous.interfaces) && previous.interfaces.length) {
        present = indexesOf(previous.interfaces);
      } else {
        try { present = indexesOf(await walk('rlifPresentName', { maxRows: 1000 })); } catch (e) { present = []; }
      }
    }
    if (needsPorts && wanted.has('bridgePorts') && present.length) {
      try { bridgeList = await resolveBridgePorts(present); } catch (e) { bridgeList = null; }
    }
    for (const [key, spec] of jobs) {
      if (needsPorts && key === 'interfaces') continue;                    // read above
      if (key === 'bridgePorts' && bridgeList) continue;                   // read above
      try {
        // Use fetchTable so column-specified tables walk only their named
        // columns. Walking the whole table OID with a row cap (the old
        // behaviour) could stop before reaching a later column - e.g. the
        // dot1x port-control/status columns (.5/.6) were never reached on a
        // targeted refresh, so they vanished from the panel after a write.
        health[key] = await readTable(key, spec);
      } catch (e) {
        health.failed.push({ what: spec.oid, error: e.message });
        health[key] = [];
      }
    }
    // No vendor interface table? Rebuild the equivalent from IF-MIB. This only
    // runs when the caller ASKED for interfaces (it is in `only`) and the
    // vendor rlifPresentTable came back empty - NOT on every partial refresh
    // that simply didn't request interfaces. Walking the full standard IF-MIB
    // is expensive (it includes every ifIndex in the stack, fitted or not), so
    // firing it on unrelated partial refreshes was hammering the CPU each poll.
  if (wanted.has('interfaces') && !health.interfaces.length) {
    const rebuilt = new Map();
    for (const [column, oid] of Object.entries(IF_MIB_FALLBACK)) {
      let results;
      try {
        results = await walk(oid, { oid, maxRows: 4000 });
      } catch (e) { continue; }
      for (const r of results || []) {
        if (r.error || r.index === undefined) continue;
        const idx = String(r.index);
        if (!rebuilt.has(idx)) rebuilt.set(idx, { index: idx });
        const row = rebuilt.get(idx);
        // ifName is preferred, but some agents leave it blank.
        if (column === 'rlifPresentName' && (r.value === '' || r.value === null)) continue;
        row[column] = r.display !== undefined && r.display !== String(r.value)
          ? { value: r.value, display: r.display } : { value: r.value };
      }
    }
    for (const row of rebuilt.values()) {
      if (!row.rlifPresentName && row.rlifPresentDescr) row.rlifPresentName = row.rlifPresentDescr;
    }

    // A stackable advertises the whole stack's ifIndex space in IF-MIB --
    // eight units of 48 ports on a C1300X, even when one 24-port unit is
    // fitted. rlifPresentTable would have listed only what exists, so with
    // it missing the fitted units have to be worked out instead. Two
    // signals, both cheap: the standard "this interface is not physically
    // there" status, and the stack table.
    const fittedUnits = new Set();
    for (const row of health.stack) {
      const unit = val(row, 'rlPhdStackUnit');
      if (unit !== undefined) fittedUnits.add(String(unit));
      else fittedUnits.add(String(row.index));
    }
    const before = rebuilt.size;
    let dropped = 0;
    const kept = [];
    for (const row of rebuilt.values()) {
      const status = row.rlifPresentOperStatus;
      const statusText = status ? String(status.display || status.value) : '';
      if (/notPresent|\(6\)/i.test(statusText)) { dropped++; continue; }
      // Names carry the unit: gi2/0/1 is on unit 2.
      const name = row.rlifPresentName
        ? String(row.rlifPresentName.display || row.rlifPresentName.value) : '';
      const unitMatch = name.match(/^[a-z]+(\d+)\/\d+\/\d+$/i);
      if (unitMatch && fittedUnits.size && !fittedUnits.has(unitMatch[1])) { dropped++; continue; }
      kept.push(row);
    }
    health.interfaces = kept.length ? kept : Array.from(rebuilt.values());
    if (dropped && kept.length) {
      health.interfacesDropped = dropped;
      health.interfacesNote = dropped + ' of ' + before + ' IF-MIB entries ignored: not physically ' +
        'present, or on a stack unit that is not fitted';
    }
    if (health.interfaces.length) {
      health.interfacesFrom = 'IF-MIB (rlifPresentTable was empty)';
      // health.js has no logger of its own by design -- it is pure data
      // shaping -- so the fact is recorded on the payload instead, where
      // the panel can show it.
    }
  }

  // Now that dot1dStpVersion has been read, fetch only the spanning-tree
  // detail that applies to the mode actually in use.
  const mode = stpFamily(health);
  if (MODE_WALKS[mode]) {
    for (const [key, spec] of Object.entries(MODE_WALKS[mode])) {
      try {
        health[key] = await fetchTable(spec);
      } catch (e) {
        health.failed.push({ what: spec.oid, error: e.message });
      }
    }
    if (mode === 'mstp') {
      try {
        for (const r of await get(MSTP_SCALARS)) {
          if (!r.error) health.scalars[(r.column || r.name).replace(/\.0$/, '')] =
            { value: r.value, display: r.display, oid: r.oid };
        }
      } catch (e) { /* not implemented; the panel copes */ }
    }
  }
  // The periodic light refresh asks for 'scalars' so the CPU/PoE graph and the
  // config-saved badge keep updating without a full collection. Read the health
  // scalar batch (one PDU) when requested.
  if (wanted.has('scalars')) {
    for (const batch of [HEALTH_SCALARS]) {
      try {
        for (const r of await get(batch)) {
          if (!r.error) health.scalars[(r.column || r.name).replace(/\.0$/, '')] = { value: r.value, display: r.display, oid: r.oid };
        }
      } catch (e) { /* model may not implement some; panel copes */ }
    }
  }
  decorateDiscovered(health);
    health.partial = true;
    health.keys = jobs.map(([key]) => key).concat(wanted.has('scalars') ? ['scalars'] : []);
    return health;
  }

  // Scalars: one PDU for system info, one for the health numbers. Anything
  // a given model does not implement comes back as a varbind error, which
  // is recorded rather than treated as a failure of the whole page.
  for (const batch of [SYSTEM_OIDS, HEALTH_SCALARS, STP_SCALARS]) {
    let res;
    try {
      res = await get(batch);
    } catch (e) {
      health.failed.push({ what: batch.join(','), error: e.message });
      continue;
    }
    for (const r of res) {
      const key = (r.column || r.name || r.oid).replace(/\.0$/, '');
      if (r.error) health.failed.push({ what: key, error: r.error });
      else health.scalars[key] = { value: r.value, display: r.display, oid: r.oid };
    }
  }

  // Walk a few tables at a time rather than one after another. Each walk is
  // many round trips, so on anything but a local switch the collection is
  // latency-bound and this is most of the wall-clock time. The limit is
  // deliberately low: a switch CPU that is already busy is exactly the one
  // you are trying to measure, and flooding it would distort the reading.
  // Fewer parallel table walks means fewer concurrent request streams and a
  // lower peak request rate on the switch. Combined with per-request pacing in
  // the walk itself, this keeps a full collection to gentle, steady traffic
  // rather than a brief high-pps burst. Tunable via env.
  const CONCURRENCY = Number(process.env.SNMP_CONCURRENCY) || 2;
  // Tables marked onDemand are NOT walked on every full collection - they are
  // large and only needed when a specific panel is open, so they are fetched by
  // that panel's targeted refresh instead. This keeps the big MAC forwarding
  // table (dot1qTpFdbTable, up to ~1500 rows) off the regular poll.
  //
  // Interfaces are read first: the list of interfaces that exist is what lets
  // every per-port table be fetched for those ports alone (readTable), and the
  // bridge-port mapping is settled once before the spanning-tree tables need it.
  try { health.interfaces = await fetchTable(TABLE_WALKS.interfaces); }
  catch (e) { health.failed.push({ what: TABLE_WALKS.interfaces.oid, error: e.message }); health.interfaces = []; }
  present = indexesOf(health.interfaces);
  if (present.length) {
    try { bridgeList = await resolveBridgePorts(present); }
    catch (e) { health.failed.push({ what: TABLE_WALKS.bridgePorts.oid, error: e.message }); bridgeList = []; }
  }
  const jobs = Object.entries(TABLE_WALKS).filter(([key, spec]) => !spec.onDemand &&
    key !== 'interfaces' && !(key === 'bridgePorts' && bridgeList));
  let next = 0;
  const worker = async () => {
    while (next < jobs.length) {
      const [key, spec] = jobs[next++];
      try {
        health[key] = await readTable(key, spec);
      } catch (e) {
        // A table this model does not implement is not fatal: record it
        // and let the panel stay hidden.
        health.failed.push({ what: spec.oid, error: e.message });
        health[key] = [];
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, jobs.length) }, worker));

  // No vendor interface table? Rebuild the equivalent from IF-MIB, so port
  // names and the "does this port exist" test still work.
  if (!health.interfaces.length) {
    const rebuilt = new Map();
    for (const [column, oid] of Object.entries(IF_MIB_FALLBACK)) {
      let results;
      try {
        results = await walk(oid, { oid, maxRows: 4000 });
      } catch (e) { continue; }
      for (const r of results || []) {
        if (r.error || r.index === undefined) continue;
        const idx = String(r.index);
        if (!rebuilt.has(idx)) rebuilt.set(idx, { index: idx });
        const row = rebuilt.get(idx);
        // ifName is preferred, but some agents leave it blank.
        if (column === 'rlifPresentName' && (r.value === '' || r.value === null)) continue;
        row[column] = r.display !== undefined && r.display !== String(r.value)
          ? { value: r.value, display: r.display } : { value: r.value };
      }
    }
    for (const row of rebuilt.values()) {
      if (!row.rlifPresentName && row.rlifPresentDescr) row.rlifPresentName = row.rlifPresentDescr;
    }

    // A stackable advertises the whole stack's ifIndex space in IF-MIB --
    // eight units of 48 ports on a C1300X, even when one 24-port unit is
    // fitted. rlifPresentTable would have listed only what exists, so with
    // it missing the fitted units have to be worked out instead. Two
    // signals, both cheap: the standard "this interface is not physically
    // there" status, and the stack table.
    const fittedUnits = new Set();
    for (const row of health.stack) {
      const unit = val(row, 'rlPhdStackUnit');
      if (unit !== undefined) fittedUnits.add(String(unit));
      else fittedUnits.add(String(row.index));
    }
    const before = rebuilt.size;
    let dropped = 0;
    const kept = [];
    for (const row of rebuilt.values()) {
      const status = row.rlifPresentOperStatus;
      const statusText = status ? String(status.display || status.value) : '';
      if (/notPresent|\(6\)/i.test(statusText)) { dropped++; continue; }
      // Names carry the unit: gi2/0/1 is on unit 2.
      const name = row.rlifPresentName
        ? String(row.rlifPresentName.display || row.rlifPresentName.value) : '';
      const unitMatch = name.match(/^[a-z]+(\d+)\/\d+\/\d+$/i);
      if (unitMatch && fittedUnits.size && !fittedUnits.has(unitMatch[1])) { dropped++; continue; }
      kept.push(row);
    }
    health.interfaces = kept.length ? kept : Array.from(rebuilt.values());
    if (dropped && kept.length) {
      health.interfacesDropped = dropped;
      health.interfacesNote = dropped + ' of ' + before + ' IF-MIB entries ignored: not physically ' +
        'present, or on a stack unit that is not fitted';
    }
    if (health.interfaces.length) {
      health.interfacesFrom = 'IF-MIB (rlifPresentTable was empty)';
      // health.js has no logger of its own by design -- it is pure data
      // shaping -- so the fact is recorded on the payload instead, where
      // the panel can show it.
    }
  }

  // Now that dot1dStpVersion has been read, fetch only the spanning-tree
  // detail that applies to the mode actually in use.
  const mode = stpFamily(health);
  if (MODE_WALKS[mode]) {
    for (const [key, spec] of Object.entries(MODE_WALKS[mode])) {
      try {
        health[key] = await fetchTable(spec);
      } catch (e) {
        health.failed.push({ what: spec.oid, error: e.message });
      }
    }
    if (mode === 'mstp') {
      try {
        for (const r of await get(MSTP_SCALARS)) {
          if (!r.error) health.scalars[(r.column || r.name).replace(/\.0$/, '')] =
            { value: r.value, display: r.display, oid: r.oid };
        }
      } catch (e) { /* not implemented; the panel copes */ }
    }
  }
  health.stpMode = mode;

  // Per-port spanning-tree state, fetched by instance rather than walked.
  if (mode === 'pvst' || mode === 'mstp') {
    const target = mode === 'pvst' ? 'pvstPorts' : 'mstpPorts';
    try {
      const result = await fetchPortInstances(get, health, mode);
      health[target] = result.rows;
      health.stpPortFetch = result.stats;
    } catch (e) {
      health.failed.push({ what: mode + ' per-port state', error: e.message });
    }
  }

  if (previous && Array.isArray(previous.interfaces)) {
    health.previousErrors = new Map(previous.interfaces.map((r) => [
      String(r.index),
      (Number(r.inErrors) || 0) + (Number(r.outErrors) || 0)
    ]));
    health.previousElapsedMs = Date.now() - previous.at;
  }

  decorateDiscovered(health);

  // Work out the model so the PSE table can be sanity checked against the
  // datasheet budget for this switch.
  health.model = detectModel([
    health.scalars.sysDescr && health.scalars.sysDescr.value,
    health.stack[0] && health.stack[0].rlPhdStackProductID && health.stack[0].rlPhdStackProductID.value
  ]);
  health.modelPoe = health.model ? MODEL_POE[health.model] || null : null;

  // Identify the product LINE (C1200 / C1300 / C1300X). This drives which MIB
  // set the Explorer shows and which features are MIB-supported (OSPF/PTP are
  // C1300X-only). detectModel above is C1300-only and returns null for the
  // other lines, so detection here reads the raw model strings the switch
  // reports (sysDescr carries the full model, e.g. "C1300X-24T-4X"). A missing
  // match leaves line null for the user to set via the per-switch override.
  const prod = products.detect([
    health.scalars.sysDescr && health.scalars.sysDescr.value,
    health.stack[0] && health.stack[0].rlPhdStackProductID && health.stack[0].rlPhdStackProductID.value,
    health.model,
    ...((health.inventory || []).map((r) => r.entPhysicalModelName &&
      (r.entPhysicalModelName.value !== undefined ? r.entPhysicalModelName.value : r.entPhysicalModelName.display)))
  ]);
  health.product = prod
    ? { line: prod.line, label: prod.label, features: prod.features || {}, detected: true }
    : { line: null, label: null, features: {}, detected: false };

  // Drop PSE rows whose budget is too small to be a real power source.
  // Keeping them would understate the budget and produce nonsense
  // utilisation figures (a 6W draw against a 2W "budget" reads as 300%).
  health.poeIgnored = [];
  health.poe = health.poe.filter((row) => {
    const budget = Number(val(row, 'pethMainPsePower'));
    if (!Number.isFinite(budget) || budget < MIN_REAL_PSE_WATTS) {
      health.poeIgnored.push({
        index: row.index,
        budget: Number.isFinite(budget) ? budget : null,
        reason: 'budget below ' + MIN_REAL_PSE_WATTS + 'W, the smallest any C1300 PoE model provides'
      });
      return false;
    }
    return true;
  });

  // Trim the interface table to the columns that matter for health.
  health.interfaces = health.interfaces.map((row) => {
    const out = { index: row.index };
    for (const c of IFACE_COLUMNS) if (row[c]) out[c] = row[c];
    return out;
  });

  // Settings tables carried from the previous collection rather than re-read.
  if (carried.length) health.carried = carried;

  health.alerts = buildAlerts(health);
  health.summary = summarise(health);
  // Working state, not payload: a Map serialises to an empty object and
  // would only confuse anyone reading the response.
  delete health.previousErrors;
  return health;
}

/**
 * Build the exact OID list for the instances that matter and GET them in
 * batches. Returns rows in the same shape pivot() produces, so everything
 * downstream is unchanged.
 */
async function fetchPortInstances(get, h, mode) {
  const pvst = mode === 'pvst';
  const columns = pvst ? PVST_PORT_COLUMNS : MSTP_PORT_COLUMNS;
  const base = pvst ? PVST_PORT_BASE : MSTP_PORT_BASE;

  const instanceIds = (pvst ? h.pvstVlans : h.mstpInstances)
    .map((r) => String(r.index))
    .filter((id) => id !== '');

  // Only bridge ports that map to an interface the switch actually has.
  const present = new Set(h.interfaces.map((r) => String(r.index)));
  const ports = [];
  for (const row of h.bridgePorts) {
    const cell = row.dot1dBasePortIfIndex;
    const ifIndex = cell ? String(cell.value) : null;
    if (ifIndex && present.has(ifIndex)) ports.push(String(row.index));
  }
  // Best available source, in order of how well it reflects reality:
  // bridge ports that map to a present interface, then the interface list
  // itself, then every bridge port the switch admits to, and only as a
  // last resort every row in dot1dStpPortTable -- that one covers the
  // whole ifIndex space (424 entries on a 24-port switch), so it is both
  // the least accurate and the most expensive.
  const portList = ports.length ? ports
    : (h.interfaces.length ? h.interfaces.map((r) => String(r.index))
      : (h.bridgePorts.length ? h.bridgePorts.map((r) => String(r.index))
        : h.stpPorts.map((r) => String(r.index))));

  const stats = {
    instances: instanceIds.length,
    ports: portList.length,
    requested: 0,
    truncated: false
  };
  if (!instanceIds.length || !portList.length) return { rows: [], stats };

  const pairs = [];
  for (const id of instanceIds) {
    for (const port of portList) {
      if (pairs.length >= MAX_PORT_INSTANCES) { stats.truncated = true; break; }
      pairs.push(id + '.' + port);
    }
    if (stats.truncated) break;
  }

  const oids = [];
  for (const suffix of pairs) {
    for (const col of Object.values(columns)) oids.push(base + '.' + col + '.' + suffix);
  }
  stats.requested = oids.length;

  const results = [];
  for (let i = 0; i < oids.length; i += GET_BATCH) {
    const batch = oids.slice(i, i + GET_BATCH);
    try {
      for (const r of await get(batch)) results.push(r);
    } catch (e) {
      // One bad batch should not lose the rest.
      stats.errors = (stats.errors || 0) + 1;
    }
  }
  return { rows: pivot(results), stats };
}

function summarise(h) {
  const up = h.interfaces.filter((i) => /^up/i.test(disp(i, 'rlifPresentOperStatus') || '')).length;
  const total = h.interfaces.length;
  const adminDown = h.interfaces.filter((i) => /^down/i.test(disp(i, 'rlifPresentAdminStatus') || '')).length;

  let poeUsed = 0, poeBudget = 0;
  for (const p of h.poe) {
    poeUsed += Number(val(p, 'pethMainPseConsumptionPower')) || 0;
    poeBudget += Number(val(p, 'pethMainPsePower')) || 0;
  }

  const temps = h.sensors
    .filter((s) => /celsius/i.test(disp(s, 'entPhySensorType') || ''))
    .map(sensorValue)
    .filter((v) => v != null);

  const total_ = Number(h.scalars.rlFileTotalSizeOfFlash && h.scalars.rlFileTotalSizeOfFlash.value);
  const free_ = Number(h.scalars.rlFileFreeSizeOfFlash && h.scalars.rlFileFreeSizeOfFlash.value);

  const sctRate = Number(h.scalars.rlSctCpuRate && h.scalars.rlSctCpuRate.value);
  const sctOn = h.scalars.rlSctCpuRateEnabled
    ? /true/i.test(h.scalars.rlSctCpuRateEnabled.display || '') : null;

  const stpBlocked = h.stpPorts.filter((p) => /blocking|discarding/i.test(disp(p, 'dot1dStpPortState') || '')).length;
  const stpForwarding = h.stpPorts.filter((p) => /forwarding/i.test(disp(p, 'dot1dStpPortState') || '')).length;

  const authedHosts = h.dot1xHosts.filter((r) => disp(r, 'rldot1xAuthMultiSessionUserName'));

  return {
    mgmtSessionCount: h.mgmtSessions.length || null,
    dot1xHostCount: authedHosts.length || null,
    dot1xLockedCount: h.dot1xLocked.length || null,
    stpMode: h.stpMode || null,
    stpPorts: h.stpPorts.length || null,
    stpForwarding: stpForwarding || null,
    stpBlocked: stpBlocked || null,
    stpIsRoot: h.stpPorts.length
      ? Number(h.scalars.dot1dStpRootPort && h.scalars.dot1dStpRootPort.value) === 0 : null,
    stpTopologyChanges: h.scalars.dot1dStpTopChanges
      ? Number(h.scalars.dot1dStpTopChanges.value) : null,
    mstpInstances: h.mstpInstances.length || null,
    pvstVlans: h.pvstVlans.length || null,
    vlanCount: h.vlans.length || null,
    neighbourCount: (h.cdp.length + h.lldp.length) || null,
    cdpCount: h.cdp.length || null,
    lldpCount: h.lldp.length || null,
    macCount: h.macTable.length || null,
    inventoryCount: h.inventory.length || null,
    model: h.model || null,
    datasheetPoeW: h.modelPoe ? h.modelPoe.watts : null,
    datasheetPoePorts: h.modelPoe ? h.modelPoe.ports : null,
    poeIgnoredCount: (h.poeIgnored || []).length,
    cpuInputPps: Number.isFinite(sctRate) ? sctRate : null,
    cpuInputEnabled: sctOn,
    interfacesUp: up,
    interfacesTotal: total,
    interfacesAdminDown: adminDown,
    // 0 W used is a real, correct reading (nothing drawing power), so it must
    // not collapse to null the way "no data" does. Report the measured value
    // whenever the PoE table had any rows; only a missing budget stays null.
    poeUsedW: h.poe.length ? poeUsed : null,
    poeBudgetW: poeBudget || null,
    maxTempC: temps.length ? Math.max(...temps) : null,
    flashFreePct: (Number.isFinite(total_) && Number.isFinite(free_) && total_ > 0)
      ? Number(((free_ / total_) * 100).toFixed(1)) : null,
    worstSeverity: ['critical', 'warning', 'ok']
      .find((sev) => h.alerts.some((a) => a.severity === sev)) || 'ok'
  };
}

module.exports = {
  collect, SYSTEM_OIDS, HEALTH_SCALARS, TABLE_WALKS, THRESHOLDS, DECORATION_DEPS, SETTINGS_TABLES,
  MODEL_POE, MIN_REAL_PSE_WATTS, detectModel, buildAlerts
};
