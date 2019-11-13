# Taxonomy of bugs

This document presents a taxonomy (classification) for bugs that apply in robotics and that is used within RVD. Content is heavily inspired by previous work related to quality:

> Based on the original work of Claus Brabrand & Andrzej Wasowski (April 3, 2017, version 1.3 )
>   https://raw.githubusercontent.com/robust-rosin/robust/60c2902d5069f015027231b4a51096b7b900bcfa/doc/taxonomy-description.txt
>

Currently, the taxonomy is somewhat ROS-centered but it <ins>aims to mature beyond ROS and into classifying any robot or robot component's bug</ins>.

Arguably, there's some intersection between quality and security bugs. Several bugs originally reported as quality ones might lead into a security vulnerability. Similarly, originally considered security bugs might turn out unexploitable, and might get later classified as quality ones. For coherence, we'll try to capture a common taxonomy that allows to reflect all types of bugs that apply to robots. Moreover the word `bug` and `flaw` will be used interchangeably. For more details on terminology, refer to https://github.com/aliasrobotics/RVD#appendix-a-vulnerabilities-weaknesses-bugs-and-more.

The following sections reason about how a to systematically capture and record a flaw in the code that might lead to quality or security issues. It details what information should be captured and in what format. <ins>It will not always be possible to perfectly fill in all fields for all bugs. In those cases, the corresponding fields should be noted as `None`. In cases where the information is not applicable, please put `N/A`  (Not Applicable)</ins>.

*NOTE: whenever a flaw is quality-related, it should be tagged using a `quality` label within RVD*
- **id**: Number of the issue/ticket in RVD.
- **title**:
	Concise textual one-line summary of the bug intended for domain non-experts (typically 10 words or 65 chars max).
- **type**: weakness | vulnerability | exposure. One among them.
- **description**:
	Textual description of the bug (typically 5-10 lines). Try to write this so that a domain non-expert software developer will be able to understand what this bug is about. This often involves writing about the *cause* of the bug (what was the underlying problem and what needed fixing) as well as the *effect* of the bug (how did the bug manifest itself), including whatever else is relevant in order to have a rough idea of the bug. (Flow Scalars (plain) are used to reflect the description.)

- **CWE**:
	The Common Weakness Enumeration (CWE) is a community-developed list of common software security weaknesses.   It is essentially a taxonomy of errors (weaknesses). We will try to use this taxonomy to classify the errors in terms of their effect; e.g.: CWE-476 (NULL Pointer Dereference). Since CWE is primarily concerned with security, it is sometimes necessary to add your own new categories (without a number identifier) not covered by the taxonomy; e.g., dependency errors, type errors, and robotics-specific weaknesses. In many cases, multiple categories are applicable. You should then pick the most appropriate category. Syntax for the CWE should follow this example: `CWE-307 (Brute Force)`
  
- **CVE**: CVE identification number (if exists of the bug). The Common Vulnerabilities and Exposures (CVE) List CVE® is an archive (dictionary according to the official source) of entries—each containing an identification number, a description, and at least one public reference—for publicly known cybersecurity vulnerabilities.

- **keywords**:
	This is a comma-separated list of key words; e.g.,: "xacro, gazebo, urdf, driver"

- **system**:
	This is an identifier for the robot system or component where the flaw applies (e.g., kobuki, motoman, mavros). If it's a confidential system, then just put the value "confidential".
- **vendor**: Vendor of the robot system or component
- **severity**:
	- **rvss_score**: Robot Vulnerability Scoring System (RVSS) numerical score ([RVSS paper](https://arxiv.org/pdf/1807.10357.pdf)).
  - **rvss_vector**: RVSS vector used to calculate the score ([RVSS paper](https://arxiv.org/pdf/1807.10357.pdf)).
  - **severity_description**: None | Low | Medium | High | Critical. One among them. Text description of the severiy. Ranges are described at [RVSS paper](https://arxiv.org/pdf/1807.10357.pdf).
  - **cvss_score**: CVSS numerical score.
  - **cvss_vector**: CVSS vector.

- **links**:
	A list of links to additional information relevant for understanding the bug.

The following fields relate to the manifestation of the bug itself which is also sometimes referred to as the effect of the bug (as opposed to the underlying cause of the bug involving how it was fixed which is covered later; cf. “FIX” below).

- **flaw**:
	- **phase**: In what phase of the software life cycle did the error occur?  Please pick the most appropriate among the following predefined options (each is accompanied by a elaborative description):
	  - `programming-time` (for errors that are detected by programmers, for instance due to a missing API, etc.)
	  - `build-time` (for errors that are reported by the build/make tools that compose the source code prior to compilation)
	  - `compile-time` (for errors that are reported by the compiler itself)
	  - `deployment-time` (for errors that occur after compilation and before the program is run; often when some deployment or installation scripts are run. This also includes “installation-time”)?
	  - `runtime-initialization` (for errors that occur when the software is run and being initialized). (Note that this including both "virtual" simulation and "real" hardware.)
	  - `runtime-operation` (for errors that occur when the software is run on normal operation after having been initialized). (Note that this including both "virtual" simulation and "real" hardware.)
	  - `testing`, either static or dynamic testing using whatever means of tools. Includes penetrating testing activites.

	- **specificity**:
		This is an open textual field about how this bug generalizes; whether it is a general software issue applicable to many or most software projects or whether it is a general robotics issue or something completely specific applicable only to the ROS or ROS-I projects. Please pick the most appropriate among the following options:
	  - `general issue` (similar issues are to be expected in many or most software projects). Heuristic: An issue is general if a single tool solving this issue could plausibly solve it for a broad class of software projects.
	  - `robotics-specific` (similar issues are to be expected in other robotics platforms).
	  - `ROS-specific` (quite idiosyncratic as to how ROS or ROS-I is built). Heuristic: If a special ROS tool is needed to solve this issue, then it is probably ROS-specific.
	  - `subject-specific` (specific to an application, robot or other robot component (other than ROS or ROS-I)).
	  - `N/A`

	- **architectural location**:
		 Where did the bug occur? Please pick one of the following two options:
	   - `application-specific code` (did the bug occur in an application)
	   - `platform code` (did the bug occur in ROS, ROS-I or other platform/framework)
	   - `third-party` (did the bug occur in ROS or ROS-I platform itself)

	- **application**:
		Describe the application where the flaw was found or `N/A`.

	- **subsystem**:
		In which subsystem (part of the organizational structure of the project) did the bug occur. The classification of the subsystem should follow <ins>`subsystem[:subsubsystem]`</ins> format with the following taxonomy (see [HRIM](https://arxiv.org/pdf/1802.01459.pdf) for related work on this). A few examples might include `cognition:planner`, `sensing:camera` or `cognition:ros2:manipulation:planner`.:
				
	  - `sensing`
		  - `camera`
		  - `depth sensor`
		  - `GPS`
		  - ...
	  - `actuation`
		  - `servo motor`
		  - `driver`
		  - `controller`
		  - ...
	  - `communication`
		  - `encryption`
		  - `switch`
		  - ...
	  - `cognition`
		  - `planner`
		  - `dds`
		  - `ros`
		  - `navigation`
		  - `manipulation`
		  - ...
	  - `UI`
		  - `teach pendant`
		  - `front screen`
		  - ...
	  - `power`
		  - `auxiliary power subsystem`
		  - `power supply`
		  - ...


	- **package**: 
	This is a newline-separated list of ROS packages involved. Each entry should specify the project, the repository, and the package involved; e.g.:
    "ros-industrial/universal_robot/ur_bringup" 
    "ros-industrial/universal_robot/ur_description"

  - **language**:
    A comma-separated list of the languages involved in the manifestation of the bug. `N/A` if the error is not explicitly reported by the language infrastructure.
   
	 Let's also try to normalize the languages: `python`, `cmake`, `C`, `C++`, `package.xml`, `launch XML`, `msg`, `srv`,  `xacro`, `urdf`.  Avoid a generic XML tag (all files in ROS have some known schema, and let's try to narrow it down when writing). Also the language should be N/A if the bug is not reported by the language infrastructure (so if the error is in package.xml but a C compiler fails then the language is "C" here, not package.xml.  The latter is listed under the fix. If the error is not reported by a language infrastructure, but for instance wrong behavior is discovered in simulation, then do not put a language in). For this reason it should be fairly unusual to have more than one language listed here.
  
	- **date-detected**: Date when the bug was detected. 
	- **detected-by**: Name of the person or group that found the bug.  
	- **detected-by-method**: How was the bug detected and by whom? Please pick the most appropriate for each one of the sub-elements and among the following predefined lists of tentative items:		
	  - `build system` (the bug was detected by the build system prior to compilation)
	  - `compiler` (the bug was detected by the compiler itself, this includes xacro, which compiles xacro files to urdf)	  
	  - `assertions` (the bug was detected by assertions statements in the code; e.g., “assert(x>0);”)
	  - `runtime detection` (the bug was detected at runtime; e.g., an exception was thrown)
	  - `runtime crash` (the bug caused the system to crash at runtime and cease functioning)
	  - `testing violation` (the bug was detected by violating a test case)
		- `testing static` (the bug was detected by a researcher performing static testing of the system, cite the specific tool as well. E.g.: "testing static, cppcheck" )
	  - `testing dynamic` (the bug was detected by a researcher performing dynamic testing of the system, cite the specific method tool as well. E.g.: "testing dynamic, fuzzing, ros2_fuzzer")

	- **date-reported**: Date when the bug was detected.
	- **reported-by**: Name of the person or group that reported the bug.
	- **reported-by-relationship**: How was the bug reported? Please pick the most appropriate among the following predefined list:
		-  `guest user` (the bug was reported by a guest user)
		-  `contributor` (the bug was reported by a developer/contributor)
		-  `developer` (the bug was reported by a member developer)
		-  `automatic` (the bug was reported by an automatic test/analyze service, including continuous integration)
		- `security researcher` (the bug was reported by a security researcher performing an assessment)
		-  `None` (the bug was not reported; e.g., because it was fixed directly without any reports)

	- **issue**:
		This is a URI reference to an issue/ticket tracker entry. This will obviously be empty if the bug is unreported (None in the fields related to "reported").  But even for some reported bugs there will be no issue created (bugs can be reported through other channels). Add reports through other channels under links (above).

	- **reproducibility**: Captures the complexity of reproducing the flaw. Typically classified as `always` | `sometimes` | `rare`

	- **trace**:
	For runtime bugs, this is a trace (call stack/sequence of function calls) to the bug. `N/A` for bugs not involving runtime (e.g., type errors or build-system bugs).

	- **reproduction**: Description on how to reproduce the flaw. N/A if the bug not reproduced.
	- **reproduction-image**: URL to the image for reproducing the flaw.

- **exploitation**: describe how to exploit the flaw (applicable to vulnerabilities).
	- **description**: Description on how to exploit the flaw. N/A if not a vulnerability.
	- **exploitation-image**: URL to the image for exploiting the flaw. Generally, `exploitation-image` and `reproduction-image` will be the same.
	- **exploitation-vector**: A series of commands, shellcode and/or scripts that perform the exploitation over the `exploitation-image`.

- **mitigation**: The following fields relate to the mitigation of the bug. Once identified,  *fixing* the bug involves removing the actual *fault* (in testing terminology) and often involves making changes in the code or infrastructure. This is not always feasible thereby in some cases, bugs might be mitigated differently by either adding layers of protection 
	- **description**: Description of the mitigation
	- **pull-request**: URI for pull request (or commit) that fixed the bug. None if no pull request (for instance direct commit).


## Examples and validation

### Weakness (quality)
Taken from https://github.com/robust-rosin/robust/blob/master/turtlebot/3390789/3390789.bug

```yaml
id: 792
title: Circular Package Dependencies
type: weakness
description: Two packages from Turtlebot declared dependencies on each other, which caused errors in the build farm.
cwe: None
cve: None
keywords: ['dependencies', 'package', 'manifest', 'build farm']
system: turtlebot
vendor: N/A
severity:
  rvss_score: None
  rvss_vector: None
  severity_description: None
  cvss_score: None
  cvss_vector: None
links: ['http://wiki.ros.org/buildfarm']
flaw:
  phase: build-time
  specificity: ROS-specific  
  architectural-location: application-specific code
  application: mobile robot
  subsystem: cognition:ros2
  package: turtlebot/turtlebot/turtlebot_bringup | turtlebot/turtlebot/turtlebot_capabilities
  languages: null
  date-detected: 2015-01-06 (23:43)
  detected-by: robust project (https://github.com/robust-rosin/robust)
  detected-by-method: build system
  date-reported: 2015-01-06 (23:43)
  reported-by: robust project (https://github.com/robust-rosin/robust)
  reported-by-relationship: member developer
  issue: https://github.com/turtlebot/turtlebot/issues/185
  reproducibility: always
  trace: ""
  reproduction: >
        An issue surfaced when building the Docker image, as it could
        not find tf2 packages. This was due to the repository being named
        `geometry_experimental` at the time this issue was reported, and
        having been renamed to `geometry2` later on. To fix this, the
        rosinstall file had to be patched manually. Cf. issue
        https://github.com/robust-rosin/robust/issues/63.
  reproduction-image: None
exploitation:
  description: None
  exploitation-image: None
  exploitation-vector: None
mitigation:
  description: Fixex through the commit.
  pull-request: https://github.com/turtlebot/turtlebot/commit/339078942cf67457bc472e07a3e75e9895ebf2f7
```

### Weakness (unspecified, thereby security-related)
Taken from https://github.com/aliasrobotics/RVD/issues/509

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

### Vulnerability
Taken from https://github.com/aliasrobotics/RVD/issues/102.

```yaml
id: 102
title: OTA OpenSSH version vulnerable to user enumeration attacks
type: vulnerability
description: The OpenSSH server version 7.6p1 is vulnerable to user enumeration attacks by timing.
cwe: CWE-307 (Brute Force)
cve: None
keywords: ['MARA', 'ros2', 'SSH', 'pentesting']
system: MARA
vendor: Acutronic Robotics
severity:
  rvss_score: 5.3
  rvss_vector: RVSS:1.0/AV:RN/AC:L/PR:N/UI:N/Y:Z/S:U/C:L/I:N/A:N/H:N
  severity_description: Medium
  cvss_score: None
  cvss_vector: None
links: ['https://github.com/AcutronicRobotics/MARA']
flaw:
  phase: testing
  specificity: general issue
  architectural-location: third-party
  application: connection with manipulator
  subsystem: communication:openssl
  package: N/A
  languages: C
  date-detected: 2019-02-10 (00:00)
  detected-by: Alias Robotics
  detected-by-method: runtime detection
  date-reported: 2019-02-10 (00:00)
  reported-by: Alias Robotics
  reported-by-relationship: security researcher
  issue: https://github.com/aliasrobotics/RVD/issues/102
  reproducibility: always
  trace: N/A
  reproduction: Not disclosed
  reproduction-image: Not disclosed
exploitation:
  description: Not disclosed
  exploitation-image: Not disclosed
  exploitation-vector: Not disclosed
mitigation:
  description: Not disclosed
  pull-request: Not disclosed

```

### Exposure

Unreported. Related to a misconfiguration in the SROS2 defaults https://github.com/ros2/sros2/blob/master/sros2/sros2/policy/defaults/dds/governance.xml#L13.

```yaml
id: N/A (pending)
title: Defaults lead to information exposure
type: weakness
description: Due to a missconfigufation of the defaults, ROS 2 node information is by default shared in plain across the ROS 2 graph.
cwe: CWE-200 (Information Exposure)
cve: None
keywords: ['defaults', 'ROS 2', 'SROS2', 'information disclosure']
system: ros2
vendor: Open Robotics
severity:
  rvss_score: None
  rvss_vector: None
  severity_description: None
  cvss_score: None
  cvss_vector: None
links: ['https://github.com/ros2/sros2/blob/master/sros2/sros2/policy/defaults/dds/governance.xml#L13']
flaw:
  phase: runtime-operation
  specificity: ROS-specific
  architectural-location: platform code
  application: security of middleware communications
  subsystem: communication:ros2:dds:sros2
  package: turtlebot/turtlebot/turtlebot_bringup | turtlebot/turtlebot/turtlebot_capabilities
  languages: XML
  date-detected: N/A (pending)
  detected-by: Alias Robotics
  detected-by-method: runtime detection
  date-reported: N/A (pending)
  reported-by: Alias Robotics
  reported-by-relationship: security researcher
  issue: N/A (pending)
  reproducibility: always
  trace: N/A
  reproduction: None (pending)    	
  reproduction-image: None (pending)    	
exploitation:
  description: None (pending)
  exploitation-image: None (pending)
  exploitation-vector: None (pending)
mitigation:
  description: None
  pull-request: None

```
