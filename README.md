# Robot Vulnerability Database (RVD)

<a href="http://www.aliasrobotics.com"><img src="https://pbs.twimg.com/profile_images/1138735160428548096/px2v9MeF.png" align="left" hspace="8" vspace="2" width="200"></a>

This repository contains Alias Robotics' Robot Vulnerability and Database (RVD), an attempt to register and record robot vulnerabilities and weaknesses. 

Vulnerabilities are rated according to the [Robot Vulnerability Scoring System (RVSS)](https://github.com/aliasrobotics/RVSS). For a discussion regarding terminology and the difference between robot vulnerabilities, robot weaknesses or robot bugs refer to [Appendix A](#appendix-a-vulnerabilities-weaknesses-bugs-and-more).

**Alias Robotics supports hacker-powered robot security in close collaboration with original robot manufacturers. By no means we encourage or promote the unauthorized tampering with running robotic systems. This can cause serious human harm and material damages.**

## Robot vulnerabilities (and weaknesses)

### General summary
*Last updated Tue, 10 Sep 2019 14:07:33*

|       | Open      | Closed  |    All |
|-------|---------|--------|-----------|
| Vulnerabilities | [![label: vulns_open][~vulns_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) | [![label: vulns_closed][~vulns_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) | [![label: vulns][~vulns]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) |
| Weaknesses | [![label: weaknesses_open][~weaknesses_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+)  | [![label: weaknesses_closed][~weaknesses_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+) | [![label: weaknesses][~weaknesses]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+) |
| Others |  [![label: others_open][~others_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+) | [![label: others_closed][~others_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+) |  [![label: others][~others]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+)|


|       |       |           |          |          |
|-------|---------|---------|----------|----------|
| Vulnerabilities (open) | [![label: vulns_critical][~vulns_critical]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+) | [![label: vulns_high][~vulns_high]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+) | [![label: vulns_medium][~vulns_medium]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+) | [![label: vulns_low][~vulns_low]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+) |


[~vulns]: https://img.shields.io/badge/vulnerabilities-49-7fe0bb.svg
[~vulns_open]: https://img.shields.io/badge/vulnerabilities-49-red.svg
[~vulns_closed]: https://img.shields.io/badge/vulnerabilities-0-green.svg
[~weaknesses]: https://img.shields.io/badge/weaknesses-59-dbf9a2.svg
[~weaknesses_open]: https://img.shields.io/badge/weaknesses-59-red.svg
[~weaknesses_closed]: https://img.shields.io/badge/weaknesses-0-green.svg
[~others]: https://img.shields.io/badge/others-0-dbf9a2.svg
[~others_open]: https://img.shields.io/badge/others-0-red.svg
[~others_closed]: https://img.shields.io/badge/others-0-green.svg
[~vulns_critical]: https://img.shields.io/badge/vuln.critical-20-ce5b50.svg
[~vulns_high]: https://img.shields.io/badge/vuln.high-21-e99695.svg
[~vulns_medium]: https://img.shields.io/badge/vuln.medium-8-e9cd95.svg
[~vulns_low]: https://img.shields.io/badge/vuln.low-0-e9e895.svg

<details><summary><b>Robot vulnerabilities by robot component</b></summary>

- General
  - [ROS](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A+ROS%22+-label%3A%22invalid%22+)
  - [ROS 2.0](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A+ROS2%22+-label%3A%22invalid%22+)
- Specific
  - [ABB's Service Box](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A+ABB%27s+Service+Box%22+-label%3A%22invalid%22)
  - [Alpha 1S android application](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A%20Alpha%201S%20android%20application%22+-label%3A%22invalid%22)
  - [IRB140's flex pendant](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=label%3A"robot+component%3A%20IRB140%27s%20flex%20pendant"+-label%3A"invalid")
  - [IRB140's main computer](https://github.com/aliasrobotics/RVDP/issues?q=is%3Aissue+is%3Aopen+label%3A%22robot+component%3A%20IRB140%27s%20main%20computer%22+-label%3A%22invalid%22)
  - [OP2 Firmware](https://github.com/aliasrobotics/RVDP/issues?q=is%3Aissue+is%3Aopen+label%3A"robot+component%3A%20OP2%20Firmware"+-label%3A"invalid")
  - [Sawyer Task Editor](https://github.com/aliasrobotics/RVDP/issues?q=is%3Aissue+is%3Aopen+label%3A"robot+component%3A%20Sawyer%20Task%20Editor"+-label%3A"invalid")
  - [Universal Robots Controller](https://github.com/aliasrobotics/RVDP/issues?q=is%3Aissue+is%3Aopen+label%3A"robot+component%3A%20Universal%20Robots%20Controller"+-label%3A"invalid")
  - [V-Sido OS](https://github.com/aliasrobotics/RVDP/issues?q=is%3Aissue+is%3Aopen+label%3A"robot+component%3A%20V-Sido%20OS"+-label%3A"invalid")

</details>

<details><summary><b>Robot vulnerabilities by robot</b></summary>

- [MARA](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A%20MARA%22+-label%3A%22invalid%22)
- [Pepper](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+Pepper%22+-label%3A%22invalid%22+)
- [Nao](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+NAO%22++-label%3A%22invalid%22+)
- [Baxter](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+Baxter%22++-label%3A%22invalid%22+)
- [Sawyer](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+Sawyer%22+-label%3A%22invalid%22)
- [UR3](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+UR3%22+-label%3A%22invalid%22+)
- [UR5](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+UR5%22+-label%3A%22invalid%22+)
- [UR10](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+UR10%22+-label%3A%22invalid%22+)
- [REEM-C](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+label%3A%22robot%3A+REEM-C%22+-label%3A%22invalid%22+)
- [Alpha 1S](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot%3A+Alpha+1S%22+-label%3A%22invalid%22+)
</details>

<details><summary><b>Robot vulnerabilities by vendor</b></summary>

- [Acutronic Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A%20Acutronic%20Robotics"+-label%3A"invalid")
- [ABB](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A%20ABB"+-label%3A"invalid")
- [PAL Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+PAL+Robotics"+-label%3A"invalid")
- [Rethink Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Rethink+Robotics"+-label%3A"invalid")
- [Softbank Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Softbank+Robotics"+-label%3A"invalid")
- [UBTech Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+UBTech+Robotics"+-label%3A"invalid")
- [Universal Robots](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Universal+Robots"+-label%3A"invalid")
- [Vecna](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Vecna"+-label%3A"invalid")

</details>

For more, visit the [complete list](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+-label%3A%22invalid%22+) of reported robot vulnerabilities.

### ROS 2
*Last updated Tue, 10 Sep 2019 14:07:33*

|       | Open      | Closed  |    All |
|-------|---------|--------|-----------|
| `ROS 2` Vulnerabilities | [![label: vulns_open_ros2][~vulns_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: vulns_closed_ros2][~vulns_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: vulns_ros2][~vulns_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |
| `ROS 2` Weaknesses | [![label: weaknesses_open_ros2][~weaknesses_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: weaknesses_closed_ros2][~weaknesses_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: weaknesses_ros2][~weaknesses_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |
| `ROS 2` Others | [![label: others_open_ros2][~others_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: others_closed_ros2][~others_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+)  | [![label: others_ros2][~others_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |


|       |       |           |          |          |
|-------|---------|---------|----------|----------|
| `ROS 2` Vulnerabilities (open) | [![label: vulns_critical_ros2][~vulns_critical_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: vulns_high_ros2][~vulns_high_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: vulns_medium_ros2][~vulns_medium_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: vulns_low_ros2][~vulns_low_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+label%3A%22robot%20component%3A%20ROS2%22+) |


[~vulns_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-0-7fe0bb.svg
[~vulns_open_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-0-red.svg
[~vulns_closed_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-0-green.svg
[~weaknesses_ros2]: https://img.shields.io/badge/ros2_weaknesses-59-dbf9a2.svg
[~weaknesses_open_ros2]: https://img.shields.io/badge/ros2_weaknesses-59-red.svg
[~weaknesses_closed_ros2]: https://img.shields.io/badge/ros2_weaknesses-0-green.svg
[~others_ros2]: https://img.shields.io/badge/ros2_others-0-dbf9a2.svg
[~others_open_ros2]: https://img.shields.io/badge/ros2_others-0-red.svg
[~others_closed_ros2]: https://img.shields.io/badge/ros2_others-0-green.svg
[~vulns_critical_ros2]: https://img.shields.io/badge/ros2_vuln.critical-0-ce5b50.svg
[~vulns_high_ros2]: https://img.shields.io/badge/ros2_vuln.high-0-e99695.svg
[~vulns_medium_ros2]: https://img.shields.io/badge/ros2_vuln.medium-0-e9cd95.svg
[~vulns_low_ros2]: https://img.shields.io/badge/ros2_vuln.low-0-e9e895.svg


[![label: ros2_package_rclcpp][~ros2_package_rclcpp]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rclcpp%22)
[![label: ros2_package_rcl_action][~ros2_package_rcl_action]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rcl_action%22)
[![label: ros2_package_rcl][~ros2_package_rcl]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rcl%22)
[![label: ros2_package_rosbag2_transport][~ros2_package_rosbag2_transport]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rosbag2_transport%22)
[![label: ros2_package_test_rclcpp][~ros2_package_test_rclcpp]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+test_rclcpp%22)
[![label: ros2_package_test_security][~ros2_package_test_security]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+test_security%22)
[![label: ros2_package_test_communication][~ros2_package_test_communication]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+test_communication%22)
[![label: ros2_package_octomap-distribution][~ros2_package_octomap-distribution]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+octomap-distribution%22)
[![label: ros2_package_geometric_shapes][~ros2_package_geometric_shapes]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+geometric_shapes%22)
[![label: ros2_package_intra_process_demo][~ros2_package_intra_process_demo]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+intra_process_demo%22)
[![label: ros2_package_rosbag2_converter_default_plugins][~ros2_package_rosbag2_converter_default_plugins]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rosbag2_converter_default_plugins%22)
[![label: ros2_package_rosbag2_storage_default_plugins][~ros2_package_rosbag2_storage_default_plugins]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rosbag2_storage_default_plugins%22)
[![label: ros2_package_rclcpp_lifecycle][~ros2_package_rclcpp_lifecycle]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rclcpp_lifecycle%22)
[![label: ros2_package_tlsf_cpp][~ros2_package_tlsf_cpp]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+tlsf_cpp%22)
[![label: ros2_package_rcl_lifecycle][~ros2_package_rcl_lifecycle]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rcl_lifecycle%22)


[~ros2_package_rclcpp]: https://img.shields.io/badge/rclcpp-1-red.svg
[~ros2_package_rcl_action]: https://img.shields.io/badge/rcl_action-2-red.svg
[~ros2_package_rcl]: https://img.shields.io/badge/rcl-5-red.svg
[~ros2_package_rosbag2_transport]: https://img.shields.io/badge/rosbag2_transport-3-red.svg
[~ros2_package_test_rclcpp]: https://img.shields.io/badge/test_rclcpp-1-red.svg
[~ros2_package_test_security]: https://img.shields.io/badge/test_security-2-red.svg
[~ros2_package_test_communication]: https://img.shields.io/badge/test_communication-15-red.svg
[~ros2_package_octomap-distribution]: https://img.shields.io/badge/octomap_distribution-4-red.svg
[~ros2_package_geometric_shapes]: https://img.shields.io/badge/geometric_shapes-10-red.svg
[~ros2_package_intra_process_demo]: https://img.shields.io/badge/intra_process_demo-2-red.svg
[~ros2_package_rosbag2_converter_default_plugins]: https://img.shields.io/badge/rosbag2_converter_default_plugins-2-red.svg
[~ros2_package_rosbag2_storage_default_plugins]: https://img.shields.io/badge/rosbag2_storage_default_plugins-1-red.svg
[~ros2_package_rclcpp_lifecycle]: https://img.shields.io/badge/rclcpp_lifecycle-1-red.svg
[~ros2_package_tlsf_cpp]: https://img.shields.io/badge/tlsf_cpp-9-red.svg
[~ros2_package_rcl_lifecycle]: https://img.shields.io/badge/rcl_lifecycle-1-red.svg


## Contributing

Vulnerabilities are community-contributed. Participants get the chance to obtain public acknowledgement by submitting a vulnerability while providing prove of it. Reports can be submitted in the form of [an issue](https://github.com/aliasrobotics/RVDP/issues/new?template=rvdp-report-template.md).

## Feedback?

Feel free to contact us if you have any requests of feedaback at **contact[at]aliasrobotics[dot]com**

#### Appendix A: Vulnerabilities, weaknesses, bugs and more
##### Discussion
[Commonly](https://en.wikipedia.org/wiki/Software_bug):
- A **(robot) software bug** is an error, flaw, failure or fault in a computer program or system that causes it to produce an incorrect or unexpected result, or to behave in unintended ways.

According to [CWE](https://cwe.mitre.org/about/faq.html#A.2):
- **(robot) software weaknesses** are errors (bugs?) that can lead to software vulnerabilities.
- **(robot) software vulnerability** is a mistake in software that can be directly used by a hacker to gain access to a system or network.

[ISO/IEC 27001](https://www.iso.org/isoiec-27001-information-security.html) defines only vulnerability:
- **(robot) vulnerability**: weakness of an asset or control that can be exploited by one or more threats

Based on all this, we'll assume that both "weakness" and "bug" refer to the same thing, an error in code that might turn into a "vulnerability" if exploitable. To establish some clear relationship:

```
 bugs == weaknesses
 weakness -> vulnerability <-> weakness is exploitable
```        
