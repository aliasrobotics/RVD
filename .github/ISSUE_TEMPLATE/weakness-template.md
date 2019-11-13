---
name: Weakness report template
about: Template to report a weakness in RVD. See https://bit.ly/2JnamaD if in doubt
title: ''
labels: weakness
assignees: ''

---

Fill in following the example below. If you need further clarifications on any of the items, refer to our [taxonomy](https://github.com/aliasrobotics/RVD/blob/master/docs/TAXONOMY.md) (remove these lines line).

```yaml
id: 509
title: tf2_ros, lock-order-inversion
type: weakness
description: tf2_ros, lock-order-inversion, eprosima::fastrtps::rtps::Sta...
cwe: None
cve: None
keywords: ['tf2_ros', 'ros2', 'testing']
system: ros2
vendor: Open Robotics
severity:
  rvss_score: None
  rvss_vector: None
  severity_description: None
  cvss_score: None
  cvss_vector: None
links: None
flaw:
  phase: testing
  specificity: ROS-specific
  architectural-location: platform code
  application: N/A
  subsystem: cognition:ros2:tf2
  package: tf2_ros
  languages: C++
  date-detected: Mon, 21 Oct 2019 17:38:55 +0000
  detected-by: Alias Robotics
  detected-by-method: testing dynamic
  date-reported: Mon, 21 Oct 2019 17:38:55 +0000
  reported-by: Alias Robotics
  reported-by-relationship: automatic
  issue: https://github.com/aliasrobotics/RVD/issues/509
  reproducibility: always
  trace: >
     #0 pthread_mutex_lock <null> (libtsan.so.0+0x3fadb)
     #1 __gthread_mutex_lock /usr/include/x86_64-linux-gnu/c++/7/bits/gthr-default.h:748 (libfastrtps.so.1+0x23813e)
     #2 __gthread_recursive_mutex_lock /usr/include/x86_64-linux-gnu/c++/7/bits/gthr-default.h:810 (libfastrtps.so.1+0x23813e)
     #3 std::recursive_timed_mutex::lock() /usr/include/c++/7/mutex:252 (libfastrtps.so.1+0x23813e)
     #4 std::unique_lock<std::recursive_timed_mutex>::lock() /usr/include/c++/7/bits/std_mutex.h:267 (libfastrtps.so.1+0x23813e)
     #5 std::unique_lock<std::recursive_timed_mutex>::unique_lock(std::recursive_timed_mutex&) /usr/include/c++/7/bits/std_mutex.h:197 (libfastrtps.so.1+0x23813e)
     #6 eprosima::fastrtps::rtps::StatefulReader::matched_writer_remove(eprosima::fastrtps::rtps::GUID_t const&) /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/rtps/reader/StatefulReader.cpp:182 (libfastrtps.so.1+0x23813e)
     #7 eprosima::fastrtps::rtps::EDPSimple::removeRemoteEndpoints(eprosima::fastrtps::rtps::ParticipantProxyData*) /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/rtps/builtin/discovery/endpoint/EDPSimple.cpp:821 (libfastrtps.so.1+0x5443d2)
     #8 eprosima::fastrtps::rtps::PDP::remove_remote_participant(eprosima::fastrtps::rtps::GUID_t const&, eprosima::fastrtps::rtps::ParticipantDiscoveryInfo::DISCOVERY_STATUS) /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/rtps/builtin/discovery/participant/PDP.cpp:899 (libfastrtps.so.1+0x4f4c80)
     #9 eprosima::fastrtps::rtps::PDPListener::onNewCacheChangeAdded(eprosima::fastrtps::rtps::RTPSReader*, eprosima::fastrtps::rtps::CacheChange_t const*) /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/rtps/builtin/discovery/participant/PDPListener.cpp:166 (libfastrtps.so.1+0x502113)
     #10 eprosima::fastrtps::rtps::StatelessReader::change_received(eprosima::fastrtps::rtps::CacheChange_t*) /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/rtps/reader/StatelessReader.cpp:166 (libfastrtps.so.1+0x23ab61)
     #11 eprosima::fastrtps::rtps::StatelessReader::processDataMsg(eprosima::fastrtps::rtps::CacheChange_t*) /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/rtps/reader/StatelessReader.cpp:321 (libfastrtps.so.1+0x23eb20)
     #12 operator() /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/rtps/messages/MessageReceiver.cpp:638 (libfastrtps.so.1+0x276040)
     #13 _M_invoke /usr/include/c++/7/bits/std_function.h:316 (libfastrtps.so.1+0x276040)
     #14 std::function<void (eprosima::fastrtps::rtps::RTPSReader*)>::operator()(eprosima::fastrtps::rtps::RTPSReader*) const /usr/include/c++/7/bits/std_function.h:706 (libfastrtps.so.1+0x28ab5b)
     #15 eprosima::fastrtps::rtps::MessageReceiver::findAllReaders(eprosima::fastrtps::rtps::EntityId_t const&, std::function<void (eprosima::fastrtps::rtps::RTPSReader*)>) /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/rtps/messages/MessageReceiver.cpp:476 (libfastrtps.so.1+0x27e6c2)
     #16 eprosima::fastrtps::rtps::MessageReceiver::proc_Submsg_Data(eprosima::fastrtps::rtps::CDRMessage_t*, eprosima::fastrtps::rtps::SubmessageHeader_t*) /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/rtps/messages/MessageReceiver.cpp:635 (libfastrtps.so.1+0x280659)
     #17 eprosima::fastrtps::rtps::MessageReceiver::processCDRMsg(eprosima::fastrtps::rtps::Locator_t const&, eprosima::fastrtps::rtps::CDRMessage_t*) /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/rtps/messages/MessageReceiver.cpp:232 (libfastrtps.so.1+0x288b07)
     #18 eprosima::fastrtps::rtps::ReceiverResource::OnDataReceived(unsigned char const*, unsigned int, eprosima::fastrtps::rtps::Locator_t const&, eprosima::fastrtps::rtps::Locator_t const&) /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/rtps/network/ReceiverResource.cpp:99 (libfastrtps.so.1+0x28ea03)
     #19 eprosima::fastrtps::rtps::UDPChannelResource::perform_listen_operation(eprosima::fastrtps::rtps::Locator_t) /opt/ros2_ws/src/eProsima/Fast-RTPS/src/cpp/transport/UDPChannelResource.cpp:62 (libfastrtps.so.1+0x3149c4)
     #20 std::thread::_State_impl<std::thread::_Invoker<std::tuple<void (eprosima::fastrtps::rtps::UDPChannelResource::*)(eprosima::fastrtps::rtps::Locator_t), eprosima::fastrtps::rtps::UDPChannelResource*, eprosima::fastrtps::rtps::Locator_t> > >::_M_run() <null> (libfastrtps.so.1+0x316c71)
     #21 <null> <null> (libstdc++.so.6+0xbd66e)
  reproduction: >
    	None provided (pending)
  reproduction-image: registry.gitlab.com/aliasrobotics/offensive/alurity/ros2/ros2:build-tsan2-commit-b2dca472a35109cece17d3e61b18af5cb9be5772
exploitation:
  description: None
  exploitation-image: None
  exploitation-vector: None
mitigation:
  description: None
  pull-request: None
```