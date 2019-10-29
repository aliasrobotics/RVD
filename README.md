[![label: upper_shield_malformed][~upper_shield_malformed]](https://github.com/aliasrobotics/RVD/labels/malformed)[![](https://img.shields.io/badge/flaws-341-red.svg)](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+)

[~upper_shield_malformed]: https://img.shields.io/badge/malformed-11-440fa8.svg
# Robot Vulnerability Database (RVD)

<a href="http://www.aliasrobotics.com"><img src="https://pbs.twimg.com/profile_images/1138735160428548096/px2v9MeF.png" align="left" hspace="8" vspace="2" width="200"></a>

This repository contains Alias Robotics' Robot Vulnerability and Database (RVD), an attempt to register and record robot vulnerabilities and weaknesses. 

Vulnerabilities are rated according to the [Robot Vulnerability Scoring System (RVSS)](https://github.com/aliasrobotics/RVSS). For a discussion regarding terminology and the difference between robot vulnerabilities, robot weaknesses or robot bugs refer to [Appendix A](#appendix-a-vulnerabilities-weaknesses-bugs-and-more).

**Alias Robotics supports hacker-powered robot security in close collaboration with original robot manufacturers. By no means we encourage or promote the unauthorized tampering with running robotic systems. This can cause serious human harm and material damages.**

## Concepts
Each RVD issue (ticket) corresponds with a flaw that is labeled appropriately. The meaning of the most relevant labels or statuses is covered below. Refer to the appendices for definitions on the terminology used:
- [![](https://img.shields.io/badge/open-green.svg?style=flat)](#): Flaw that remains active or under research.
- [![](https://img.shields.io/badge/closed-red.svg?style=flat)](#): Flaw that is inactive. Reasons for inactivity relate to mitigations, duplicates, erroneous reports or similar.
- [![](https://img.shields.io/badge/invalid-red.svg?style=flat)](#): Ticket discarded and removed for the overall count. This label flags invalid or failed reports including tests and related.
- [![](https://img.shields.io/badge/duplicate-cfd3d7.svg?style=flat)](#): Duplicated flaw. Typically, a link to the original ticket is provided.
- [![](https://img.shields.io/badge/malformed-440fa8.svg?style=flat)](https://github.com/aliasrobotics/RVD/labels/malformed): Flaw has a malformed syntax. Refer to the templates for basic guidelines on the right syntax.
- [![](https://img.shields.io/badge/mitigated-aaf9a7.svg?style=flat)](#): Mitigated. A link to the corresponding mitigation is required.
- [![](https://img.shields.io/badge/quality-ddb140.svg?style=flat)](#): Indicates that the bug is a quality one instead of a security flaw.
- [![](https://img.shields.io/badge/exposure-ccfc2d.svg?style=flat)](#): Indicates that flaw is an exposure.
- [![](https://img.shields.io/badge/weakness-dbf9a2.svg?style=flat)](#): Indicates that flaw is a weakness.
- [![](https://img.shields.io/badge/vulnerability-7fe0bb.svg?style=flat)](#): Indicates that flaw is a vulnerability.
- [![](https://img.shields.io/badge/severity_critical-ce5b50.svg?style=flat)](#) [![](https://img.shields.io/badge/severity_high-e99695.svg?style=flat)](#) [![](https://img.shields.io/badge/severity_medium-e9cd95.svg?style=flat)](#): Indicates the severity of the vunerability according to RVSS.

## ToC

- [Robot vulnerabilities (and weaknesses)](#robot-vulnerabilities-and-weaknesses)
	- [Concepts](#concepts)
    - [Table of contents](#toc)
    - [General summary](#general-summary)
	- [ROS 2](#ros-2)
		- [ROS 2 flaws by package (only `open` ones)](#ros-2-flaws-by-package-only-open-ones)
- [Disclosure policy](#disclosure-policy)
	- [Methodology](#methodology)
	- [FAQ](#faq)
- [Contributing, reporting a vulnerability](#contributing-reporting-a-vulnerability)
- [Contact us or send feedback](#contact-us-or-send-feedback)
	- [Automatic pings for manufacturers](#automatic-pings-for-manufacturers)
- [Appendices](#appendices)
	- [Appendix A: Vulnerabilities, weaknesses, bugs and more](#appendix-a-vulnerabilities-weaknesses-bugs-and-more)
		- [Discussion](#discussion)

## Robot vulnerabilities (and weaknesses)

### General summary
*Last updated Tue, 29 Oct 2019 13:22:49 GMT*

|       | Open      | Closed  |    All |
|-------|---------|--------|-----------|
| Vulnerabilities | [![label: vulns_open][~vulns_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) | [![label: vulns_closed][~vulns_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) | [![label: vulns][~vulns]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+) |
| Weaknesses | [![label: weaknesses_open][~weaknesses_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+)  | [![label: weaknesses_closed][~weaknesses_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+label%3Aweakness+-label%3A%22invalid%22) | [![label: weaknesses][~weaknesses]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+) |
| Others |  [![label: others_open][~others_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+) | [![label: others_closed][~others_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+) |  [![label: others][~others]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+)|


|       |       |           |          |          |
|-------|---------|---------|----------|----------|
| Vulnerabilities (open) | [![label: vulns_critical][~vulns_critical]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+) | [![label: vulns_high][~vulns_high]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+) | [![label: vulns_medium][~vulns_medium]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+) | [![label: vulns_low][~vulns_low]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+) |


[~vulns]: https://img.shields.io/badge/vulnerabilities-49-7fe0bb.svg
[~vulns_open]: https://img.shields.io/badge/vulnerabilities-49-red.svg
[~vulns_closed]: https://img.shields.io/badge/vulnerabilities-0-green.svg
[~weaknesses]: https://img.shields.io/badge/weaknesses-314-dbf9a2.svg
[~weaknesses_open]: https://img.shields.io/badge/weaknesses-292-red.svg
[~weaknesses_closed]: https://img.shields.io/badge/weaknesses-22-green.svg
[~others]: https://img.shields.io/badge/others-0-dbf9a2.svg
[~others_open]: https://img.shields.io/badge/others-0-red.svg
[~others_closed]: https://img.shields.io/badge/others-0-green.svg
[~vulns_critical]: https://img.shields.io/badge/vuln.critical-20-ce5b50.svg
[~vulns_high]: https://img.shields.io/badge/vuln.high-21-e99695.svg
[~vulns_medium]: https://img.shields.io/badge/vuln.medium-8-e9cd95.svg
[~vulns_low]: https://img.shields.io/badge/vuln.low-0-e9e895.svg

<details><summary><b>Robot vulnerabilities by robot component</b></summary>

By robot components, we consider both software and hardware robot components.

- Community robot components
  - [ROS](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A+ROS%22+-label%3A%22invalid%22+)
  - [ROS 2.0](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A+ROS2%22+-label%3A%22invalid%22+)
  - [navigation2](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22robot+component%3A+navigation2%22)
  - [moveit2](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22robot+component%3A+moveit2%22)

- Vendor-specific robot components
  - [ABB's Service Box](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A+ABB%27s+Service+Box%22+-label%3A%22invalid%22)
  - [Alpha 1S android application](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=label%3A%22robot+component%3A%20Alpha%201S%20android%20application%22+-label%3A%22invalid%22)
  - [FastRTPS](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22robot+component%3A+FastRTPS%22)
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
- [eProsima](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+eProsima"+-label%3A"invalid")
- [PAL Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+PAL+Robotics"+-label%3A"invalid")
- [Rethink Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Rethink+Robotics"+-label%3A"invalid")
- [Softbank Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Softbank+Robotics"+-label%3A"invalid")
- [UBTech Robotics](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+UBTech+Robotics"+-label%3A"invalid")
- [Universal Robots](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Universal+Robots"+-label%3A"invalid")
- [Vecna](https://github.com/aliasrobotics/RVDP/issues?utf8=✓&q=is%3Aissue+label%3A"vendor%3A+Vecna"+-label%3A"invalid")

</details>

For more, visit the [complete list](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+-label%3A%22invalid%22+) of reported robot vulnerabilities.

### ROS 2
*Last updated Tue, 29 Oct 2019 13:22:49 GMT*

|       | Open      | Closed  |    All |
|-------|---------|--------|-----------|
| `ROS 2` Vulnerabilities | [![label: vulns_open_ros2][~vulns_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: vulns_closed_ros2][~vulns_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: vulns_ros2][~vulns_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |
| `ROS 2` Weaknesses | [![label: weaknesses_open_ros2][~weaknesses_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: weaknesses_closed_ros2][~weaknesses_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot+component%3A+ROS2%22+) | [![label: weaknesses_ros2][~weaknesses_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Aweakness+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |
| `ROS 2` Others | [![label: others_open_ros2][~others_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: others_closed_ros2][~others_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+)  | [![label: others_ros2][~others_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=-label%3Aweakness+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+) |


|       |       |           |          |          |
|-------|---------|---------|----------|----------|
| `ROS 2` Vulnerabilities (open) | [![label: vulns_critical_ros2][~vulns_critical_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: vulns_high_ros2][~vulns_high_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: vulns_medium_ros2][~vulns_medium_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+label%3A%22robot%20component%3A%20ROS2%22+) | [![label: vulns_low_ros2][~vulns_low_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+label%3A%22robot%20component%3A%20ROS2%22+) |


[~vulns_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-0-7fe0bb.svg
[~vulns_open_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-0-red.svg
[~vulns_closed_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-0-green.svg
[~weaknesses_ros2]: https://img.shields.io/badge/ros2_weaknesses-313-dbf9a2.svg
[~weaknesses_open_ros2]: https://img.shields.io/badge/ros2_weaknesses-291-red.svg
[~weaknesses_closed_ros2]: https://img.shields.io/badge/ros2_weaknesses-22-green.svg
[~others_ros2]: https://img.shields.io/badge/ros2_others-0-dbf9a2.svg
[~others_open_ros2]: https://img.shields.io/badge/ros2_others-0-red.svg
[~others_closed_ros2]: https://img.shields.io/badge/ros2_others-0-green.svg
[~vulns_critical_ros2]: https://img.shields.io/badge/ros2_vuln.critical-0-ce5b50.svg
[~vulns_high_ros2]: https://img.shields.io/badge/ros2_vuln.high-0-e99695.svg
[~vulns_medium_ros2]: https://img.shields.io/badge/ros2_vuln.medium-0-e9cd95.svg
[~vulns_low_ros2]: https://img.shields.io/badge/ros2_vuln.low-0-e9e895.svg


#### ROS 2 flaws by package (only `open` ones)
[![label: ros2_package_tf2_ros][~ros2_package_tf2_ros]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+tf2_ros%22)
[![label: ros2_package_rcl_action][~ros2_package_rcl_action]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rcl_action%22)
[![label: ros2_package_rcl][~ros2_package_rcl]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rcl%22)
[![label: ros2_package_message_filters][~ros2_package_message_filters]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+message_filters%22)
[![label: ros2_package_rclcpp][~ros2_package_rclcpp]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rclcpp%22)
[![label: ros2_package_rclcpp_action][~ros2_package_rclcpp_action]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rclcpp_action%22)
[![label: ros2_package_nav2_util][~ros2_package_nav2_util]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+nav2_util%22)
[![label: ros2_package_image_transport][~ros2_package_image_transport]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+image_transport%22)
[![label: ros2_package_nav2_recoveries][~ros2_package_nav2_recoveries]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+nav2_recoveries%22)
[![label: ros2_package_nav2_map_server][~ros2_package_nav2_map_server]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+nav2_map_server%22)
[![label: ros2_package_rviz_common][~ros2_package_rviz_common]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rviz_common%22)
[![label: ros2_package_class_loader][~ros2_package_class_loader]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+class_loader%22)
[![label: ros2_package_rviz_default_plugins][~ros2_package_rviz_default_plugins]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rviz_default_plugins%22)
[![label: ros2_package_composition][~ros2_package_composition]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+composition%22)
[![label: ros2_package_demo_nodes_cpp][~ros2_package_demo_nodes_cpp]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+demo_nodes_cpp%22)
[![label: ros2_package_image_tools][~ros2_package_image_tools]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+image_tools%22)
[![label: ros2_package_demo_nodes_cpp_native][~ros2_package_demo_nodes_cpp_native]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+demo_nodes_cpp_native%22)
[![label: ros2_package_interactive_markers][~ros2_package_interactive_markers]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+interactive_markers%22)
[![label: ros2_package_logging_demo][~ros2_package_logging_demo]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+logging_demo%22)
[![label: ros2_package_rcl_yaml_param_parser][~ros2_package_rcl_yaml_param_parser]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rcl_yaml_param_parser%22)
[![label: ros2_package_nav2_costmap_2d][~ros2_package_nav2_costmap_2d]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+nav2_costmap_2d%22)
[![label: ros2_package_rosbag2_transport][~ros2_package_rosbag2_transport]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rosbag2_transport%22)
[![label: ros2_package_test_rclcpp][~ros2_package_test_rclcpp]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+test_rclcpp%22)
[![label: ros2_package_test_security][~ros2_package_test_security]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+test_security%22)
[![label: ros2_package_test_communication][~ros2_package_test_communication]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+test_communication%22)
[![label: ros2_package_octomap-distribution][~ros2_package_octomap-distribution]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+octomap-distribution%22)
[![label: ros2_package_geometric_shapes][~ros2_package_geometric_shapes]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+geometric_shapes%22)
[![label: ros2_package_intra_process_demo][~ros2_package_intra_process_demo]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+intra_process_demo%22)
[![label: ros2_package_rosbag2_converter_default_plugins][~ros2_package_rosbag2_converter_default_plugins]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rosbag2_converter_default_plugins%22)
[![label: ros2_package_rosbag2_storage_default_plugins][~ros2_package_rosbag2_storage_default_plugins]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+rosbag2_storage_default_plugins%22)
[![label: ros2_package_tlsf_cpp][~ros2_package_tlsf_cpp]](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3A%22package%3A+tlsf_cpp%22)


[~ros2_package_tf2_ros]: https://img.shields.io/badge/tf2_ros-25-red.svg
[~ros2_package_rcl_action]: https://img.shields.io/badge/rcl_action-23-red.svg
[~ros2_package_rcl]: https://img.shields.io/badge/rcl-47-red.svg
[~ros2_package_message_filters]: https://img.shields.io/badge/message_filters-18-red.svg
[~ros2_package_rclcpp]: https://img.shields.io/badge/rclcpp-22-red.svg
[~ros2_package_rclcpp_action]: https://img.shields.io/badge/rclcpp_action-24-red.svg
[~ros2_package_nav2_util]: https://img.shields.io/badge/nav2_util-33-red.svg
[~ros2_package_image_transport]: https://img.shields.io/badge/image_transport-13-red.svg
[~ros2_package_nav2_recoveries]: https://img.shields.io/badge/nav2_recoveries-13-red.svg
[~ros2_package_nav2_map_server]: https://img.shields.io/badge/nav2_map_server-3-red.svg
[~ros2_package_rviz_common]: https://img.shields.io/badge/rviz_common-2-red.svg
[~ros2_package_class_loader]: https://img.shields.io/badge/class_loader-2-red.svg
[~ros2_package_rviz_default_plugins]: https://img.shields.io/badge/rviz_default_plugins-4-red.svg
[~ros2_package_composition]: https://img.shields.io/badge/composition-3-red.svg
[~ros2_package_demo_nodes_cpp]: https://img.shields.io/badge/demo_nodes_cpp-2-red.svg
[~ros2_package_image_tools]: https://img.shields.io/badge/image_tools-2-red.svg
[~ros2_package_demo_nodes_cpp_native]: https://img.shields.io/badge/demo_nodes_cpp_native-2-red.svg
[~ros2_package_interactive_markers]: https://img.shields.io/badge/interactive_markers-1-red.svg
[~ros2_package_logging_demo]: https://img.shields.io/badge/logging_demo-1-red.svg
[~ros2_package_rcl_yaml_param_parser]: https://img.shields.io/badge/rcl_yaml_param_parser-2-red.svg
[~ros2_package_nav2_costmap_2d]: https://img.shields.io/badge/nav2_costmap_2d-4-red.svg
[~ros2_package_rosbag2_transport]: https://img.shields.io/badge/rosbag2_transport-3-red.svg
[~ros2_package_test_rclcpp]: https://img.shields.io/badge/test_rclcpp-1-red.svg
[~ros2_package_test_security]: https://img.shields.io/badge/test_security-2-red.svg
[~ros2_package_test_communication]: https://img.shields.io/badge/test_communication-2-red.svg
[~ros2_package_octomap-distribution]: https://img.shields.io/badge/octomap_distribution-4-red.svg
[~ros2_package_geometric_shapes]: https://img.shields.io/badge/geometric_shapes-10-red.svg
[~ros2_package_intra_process_demo]: https://img.shields.io/badge/intra_process_demo-2-red.svg
[~ros2_package_rosbag2_converter_default_plugins]: https://img.shields.io/badge/rosbag2_converter_default_plugins-2-red.svg
[~ros2_package_rosbag2_storage_default_plugins]: https://img.shields.io/badge/rosbag2_storage_default_plugins-1-red.svg
[~ros2_package_tlsf_cpp]: https://img.shields.io/badge/tlsf_cpp-9-red.svg



## Disclosure policy

*Our disclosure policy is highly inspired by [Google's Project Zero](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-faq.html). TL;DR, we apply a 90-day disclosure deadline for new vulnerabilities*.

*This policy is strongly in line with our desire to improve the robotics industry response times to security bugs, but also results in softer landings for bugs marginally over deadline. According to [our research](https://arxiv.org/pdf/1806.06681.pdf), most vendors are ignoring security flaws completely. We call on all researchers to adopt disclosure deadlines in some form, and feel free to use our policy verbatim (we've actually done so, from [Google's](https://www.google.com/about/appsecurity/)) if you find our record and reasoning compelling. Creating pressure towards more reasonably-timed fixes will result in smaller windows of opportunity for blackhats to abuse vulnerabilities. Given the direct physical connection with the world that robots have,  in our opinion, vulnerability disclosure policies such as ours result in greater security in robotics and an overall improved safety. A security-first approach is a must to ensure safe robotic operations.*

Alias Robotics believes that vulnerability disclosure is a two-way street where both vendors and researchers, must act responsibly.  We adhere to a **90-day disclosure deadline for new vulnerabilities** while other flaws such as simple bugs or weaknesses could be filed at any point in time (refer to [Appendix A](#appendix-a-vulnerabilities-weaknesses-bugs-and-more) for the difference between vulnerabilities, weaknesses and bugs). We notify vendors of vulnerabilities immediately, with **details shared in public with the defensive community after 90 days**, or sooner if the vendor releases a fix.

Similar to Google's policy, we want to acknowledge that the deadline can vary in the following ways:

- If a deadline is due to expire on a weekend or public holiday, the deadline will be moved to the next normal work day.
  
- Before the 90-day deadline has expired, if a vendor lets us know that a patch is scheduled for release on a specific day that will fall within 14 days following the deadline, we will delay the public disclosure until the availability of the patch.

- When we observe a previously unknown and unpatched vulnerability in software under active exploitation (a “0day”), we believe that more urgent action—within 7 days—is appropriate. The reason for this special designation is that each day an actively exploited vulnerability remains undisclosed to the public and unpatched, more devices or accounts will be compromised. Seven days is an aggressive timeline and may be too short for some vendors to update their products, but it should be enough time to publish advice about possible mitigations, such as temporarily disabling a service, restricting access, or contacting the vendor for more information. As a result, after 7 days have elapsed without a patch or advisory, we will support researchers making details available so that users can take steps to protect themselves.

Alias Robotics reserves the right to bring deadlines forwards or backwards based on extreme circumstances. We remain committed to treating all vendors strictly equally and we expect to be held to the same standard.

## CI/CD setup
In an attempt to lower the overall effort to maintain the Robot Vulnerability Database, RVD attempts to make active use of Continuous Integration (CI) and Continuous Deployment (CD) techniques through Github Actions. See our [configurations here](.github/workflows). Contributions and new ideas to this section are welcome. Please submit a Pull Request with your proposal or enhancement.

Below we list some of the existing capabilities and some tentative ones:
- [x] Comparison of stack trace before flaw submission to avoid duplicates (perfomed upstream) [refer to import_ros2.py](https://github.com/aliasrobotics/RVD/blob/master/scripts/import_ros2.py#L221)
- [x] Markdown parser that conforms with [RVD templates](.github/ISSUE_TEMPLATE/) [refer to parser.py](https://github.com/aliasrobotics/RVD/blob/master/scripts/parser/parser.py)
- [x] Automatic flaw-syntax evaluation (based on parser), tags tickets as `malformed` when applicable [refer to malformed.py#L104-L188](https://github.com/aliasrobotics/RVD/blob/master/scripts/malformed.py#L104-L188)
- [x] Automatic feedback on flaw-syntax, introduced in tickets directly as a comment [refer to malformed.py#L190-L252](https://github.com/aliasrobotics/RVD/blob/master/scripts/malformed.py#L190-L252)
- [ ] Automatic review and cross-reference of duplicated flaws, based on ticket body content and comments
- [ ] Automatic and periodic review of security advisories "in search" for robot-related vulnerabilities
- [ ] Automatic and periodic review of NVD "in search" for robot-related vulnerabilities
- [ ] Automatic and periodic review of CVE List "in search" for robot-related vulnerabilities
- [ ] CWE ID parser and validation method to conform with official CWE guidelines
- [ ] Automatic CWE ID validation mechanism (and feedback) in all tickets. Upgrade flaw-syntax evaluation.
- [ ] RVSS parser and validation to conform with RVSSv1.0 spec.
- [ ] Automatic RVSS validation mechanism (and feedback) in all tickets. Upgrade flaw-syntax evaluation.


## Contributing, reporting a vulnerability

Vulnerabilities are community-contributed. If you believe you have discovered a vulnerability in a robot or robot component (either software or hardware), obtain public acknowledgement by submitting a vulnerability while providing prove of it. Reports can be submitted in the form of [an issue](https://github.com/aliasrobotics/RVDP/issues/new?template=vulnerability-template.md).

If you wish to contribute to the RVD repository's content, please note that this document (`README.md`) is generated automatically. Submit the corresponding PRs by looking at the `scripts/` folder. If you need some inspiration or ideas to contribute, refer to [CI/CD setup](#ci/cd-setup).

## Contact us or send feedback

Feel free to contact us if you have any requests of feedaback at **contact[at]aliasrobotics[dot]com**

### Automatic pings for manufacturers
By default, new vulnerabilities are reported to manufacturers and/or open source projects however other flaws aren't. Alias Robotics can inform manufacturers directly when weaknesses are reported. If you're interested in this service, contact **contact[at]aliasrobotics[dot]com**.

## Appendices

### Appendix A: Vulnerabilities, weaknesses, bugs and more
#### Research on terminology
[Commonly](https://en.wikipedia.org/wiki/Software_bug):
- A **software `bug`** is an error, flaw, failure or fault in a computer program or system that causes it to produce an incorrect or unexpected result, or to behave in unintended ways.

According to [CWE](https://cwe.mitre.org/about/faq.html#A.2):
- **software `weaknesses`** are errors (bugs) that can lead to software vulnerabilities.
- **software `vulnerability`** is a mistake in software that can be directly used by a hacker to gain access to a system or network.

Moreover, according to [CVE page](https://cve.mitre.org/about/faqs.html#what_is_vulnerability):
- A `vulnerability` is a `weakness` in the computational logic (e.g., code) found in software and some hardware components (e.g., firmware) that, when exploited, results in a negative impact to confidentiality, integrity or availability (more [here](https://cve.mitre.org/about/terminology.html)).
- An `exposure` is a system configuration issue or a mistake in software that allows access to information or capabilities that can be used by a hacker as a stepping-stone into a system or network.

[ISO/IEC 27001](https://www.iso.org/isoiec-27001-information-security.html) defines only vulnerability:
- **(robot) vulnerability**: weakness of an asset or control that can be exploited by one or more threats

#### Discussion and interpretation 

From the definitions above, it seems reasonable to associate use interchangeably `bugs` and `flaws` when referring to security issues. In addition, the word `weakness` seems applicable to any flaw that might turn into a `vulnerability` however it must be noted that (from the text above) a `vulnerability` "must be exploited"). Based on this a clear difference can be established classifiying flaws with potential to be exploitable as `weaknesses` and flaws exploitable as `vulnerabilities`. Ortogonal to this appear `exposures` which refer to misconfigurations that allows attackers to establish an attack vector in a system.

Based in all of the above, we interpret and make the following assumptions for RVD:
- unless specified, all `flaws` are "security flaws" (an alternative could be a quality bug)
- `flaw` and `bug` refer to the same thing and can be used interchangeably
- `weakness` is a flaw with potential to be exploited (but unconfirmed its exploitability)
- `vulnerability` is a weakness that is exploitable.
- `exposure` is a configuration error or mistake in software that *without leading to exploitation*, leaks relevant information that empowers an attacker.

### Appendix B: How does RVD relate to CVE, the CVE List and the NVD?

Some definitions:
- `Robot Vulnerability Database (RVD)` is a database for robot vulnerabilities and weaknesses that aims to record and categorize flaws that apply to robot and robot components. RVD was created as a community-contributed and open archive of robot security flaws. It was originally created and sponsored by Alias Robotics.
- `Common Vulnerabilities and Exposures (CVE)` List CVE® is an archive (dictionary according to the official source) of entries—each containing an identification number, a description, and at least one public reference—for publicly known cybersecurity vulnerabilities. CVE contains vulnerabilities and exposures and is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA). It is **not** a database (see [official information](https://cve.mitre.org/about/faqs.html)). CVE List *feeds* vulnerability databases (such as the National Vulnerability Database (NVD)) with its entries and also acts as an aggregator of vulnerabilities and exposures reported at NVD.
- `U.S. National Vulnerability Database (NVD)` is the U.S. government repository of standards based vulnerability management data. It presents an archive with vulnerabilities, each with their corresponding CVE identifiers. NVD gets fed by the CVE List and then builds upon the information included in CVE Entries to provide enhanced information for each entry such as fix information, severity scores, and impact ratings. 

RVD does **not** aim to replace CVE but to <ins>complement it for the domain of robotics</ins>. RVD aims to become CVE-compatible (see [official guidelines for compatibility](https://cve.mitre.org/compatible/guidelines.html)) by tackling aspects such scope and impact of the flaws (through a proper severity scoring mechanism for robots), information for facilitating mitigation, detailed technical information, etc. For a more detailed discussion, see [this ROS Discourse thread](https://discourse.ros.org/t/introducing-the-robot-vulnerability-database/11105/7?u=vmayoral). 

When compared to other vulnerability databases, RVD aims to differenciate itself by focusing on the following:
- **robot specific**: RVD aims to focus and capture robot-specific flaws. If a flaw does not end-up applying to a robot or a robot component then it should not be recorded here.
- **community-oriented**: while RVD is originally sponsored by Alias Robotics, it aims to become community-managed and contributed.
- **facilitates reproducing robot flaws**: Working with robots is very time consuming. Mitigating a vulnerability or a weakness requires one to first reproduce the flaw. This can be extremely time consuming. Not so much providing the fix itself but ensuring that your environment is appropriate. At RVD, each flaw entry should aim to include a row named as `Module URL`. This should correspond with the link to a Docker image that should allow anyone reproduce the flaw easily.
- **robot-specific severity scoring**: opposed to CVSS which has strong limitations when applied to robotics, RVD uses RVSS, a robot-specific scoring mechanism.

As part of RVD, we encourage security researchers to file CVE Entries and use official CVE identifiers for their reports and discussions at RVD.


***
<!--
    ROSIN acknowledgement from the ROSIN press kit
    @ https://github.com/rosin-project/press_kit
-->

<a href="http://rosin-project.eu">
  <img src="http://rosin-project.eu/wp-content/uploads/rosin_ack_logo_wide.png"
       alt="rosin_logo" height="60" >
</a></br>

Supported by ROSIN - ROS-Industrial Quality-Assured Robot Software Components.
More information: <a href="http://rosin-project.eu">rosin-project.eu</a>

<img src="http://rosin-project.eu/wp-content/uploads/rosin_eu_flag.jpg"
     alt="eu_flag" height="45" align="left" >

This repository was partly funded by ROSIN RedROS2-I FTP which received funding from the European Union’s Horizon 2020
research and innovation programme under the project ROSIN with the grant agreement No 732287.

