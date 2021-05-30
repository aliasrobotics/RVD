[![](https://img.shields.io/badge/vulnerabilities-221-red.svg)](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aall+label%3Avulnerability+)
[![](https://img.shields.io/badge/bugs-0-f7b6b2.svg)](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aall+label%3Abug+)
[![](https://img.shields.io/badge/malformed-0-440fa8.svg)](https://github.com/aliasrobotics/RVD/labels/malformed)
[![](https://img.shields.io/badge/triage-62-ffe89e.svg)](https://github.com/aliasrobotics/RVD/labels/triage)
[![](https://img.shields.io/badge/duplicates-0-cfd3d7.svg)](https://github.com/aliasrobotics/RVD/labels/duplicate)

# Robot Vulnerability Database (RVD)

<a href="http://www.aliasrobotics.com"><img src="https://www.massrobotics.org/wp-content/uploads/2019/01/Alias-logo.png" align="left" hspace="8" vspace="2" width="200"></a>

[![Article](https://img.shields.io/badge/article-arxiv%3A1912.11299-red.svg)](https://arxiv.org/pdf/1912.11299.pdf)

This repository contains the Robot Vulnerability and Database (RVD), an attempt to register and record robot vulnerabilities and bugs.

Vulnerabilities are rated according to the [Robot Vulnerability Scoring System (RVSS)](https://github.com/aliasrobotics/RVSS).
For a discussion regarding terminology and the difference between robot vulnerabilities, robot weaknesses, robot bugs or others
refer to [Appendix A](#appendix-a-vulnerabilities-weaknesses-bugs-and-more).

**As main contributor, Alias Robotics supports and offers robot cybersecurity activities in close collaboration
with original robot manufacturers. By no means Alias encourages or promote the unauthorized
tampering with running robotic systems. This can cause serious human harm and material
damages.**

*Last updated Sun, 30 May 2021 06:48:42 GMT*

|       | Open      | Closed  |    All |
|-------|---------|--------|-----------|
| Vulnerabilities | [![label: vulns_open][~vulns_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+-label%3A%22duplicate%22+) | [![label: vulns_closed][~vulns_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+label%3Avulnerability+-label%3A%22invalid%22+-label%3A%22duplicate%22+) | [![label: vulns][~vulns]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+label%3Avulnerability+-label%3A%22invalid%22+-label%3A%22duplicate%22+) |
| Bugs | [![label: bugs_open][~bugs_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Abug+-label%3A%22invalid%22+-label%3A%22duplicate%22+)  | [![label: bugs_closed][~bugs_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+label%3Abug+-label%3A%22invalid%22+-label%3A%22duplicate%22+) | [![label: bugs][~bugs]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+label%3Abug+-label%3A%22invalid%22+-label%3A%22duplicate%22+) |
| Others |  [![label: others_open][~others_open]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Abug+-label%3Avulnerability+-label%3A%22invalid%22+-label%3A%22duplicate%22+) | [![label: others_closed][~others_closed]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+-label%3Abug+-label%3Avulnerability+-label%3A%22invalid%22+-label%3A%22duplicate%22+) |  [![label: others][~others]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=-label%3Abug+-label%3Avulnerability+-label%3A%22invalid%22+-label%3A%22duplicate%22+)|


|       |       |           |          |          |
|-------|---------|---------|----------|----------|
| Vulnerabilities (open) | [![label: vulns_critical][~vulns_critical]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+-label%3A%22duplicate%22+) | [![label: vulns_high][~vulns_high]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+-label%3A%22duplicate%22+) | [![label: vulns_medium][~vulns_medium]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+-label%3A%22duplicate%22+) | [![label: vulns_low][~vulns_low]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+-label%3A%22duplicate%22+) |


[~vulns]: https://img.shields.io/badge/vulnerabilities-238-7fe0bb.svg
[~vulns_open]: https://img.shields.io/badge/vulnerabilities-221-red.svg
[~vulns_closed]: https://img.shields.io/badge/vulnerabilities-17-green.svg
[~bugs]: https://img.shields.io/badge/bugs-1778-dbf9a2.svg
[~bugs_open]: https://img.shields.io/badge/bugs-0-red.svg
[~bugs_closed]: https://img.shields.io/badge/bugs-1778-green.svg
[~others]: https://img.shields.io/badge/others-2-dbf9a2.svg
[~others_open]: https://img.shields.io/badge/others-0-red.svg
[~others_closed]: https://img.shields.io/badge/others-2-green.svg
[~vulns_critical]: https://img.shields.io/badge/vuln.critical-62-ce5b50.svg
[~vulns_high]: https://img.shields.io/badge/vuln.high-79-e99695.svg
[~vulns_medium]: https://img.shields.io/badge/vuln.medium-34-e9cd95.svg
[~vulns_low]: https://img.shields.io/badge/vuln.low-2-e9e895.svg


<details><summary><b>Robot vulnerabilities by robot component</b></summary>

By robot components, we consider both software and hardware robot components
- [`robot component: Intel NUC`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20Intel%20NUC)
- [`robot component: ABB RobotStudio 5.6x`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20RobotStudio%205.6x)
- [`robot component: ABB RobotStudio Lite`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20RobotStudio%20Lite)
- [`robot component: ABB Interlink Module`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20Interlink%20Module)
- [`robot component: Robotware`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20Robotware)
- [`robot component: VxWorks`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20VxWorks)
- [`robot component: ABB WebWare Server`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20WebWare%20Server)
- [`robot component: VSN300 WiFi Logger Card`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20VSN300%20WiFi%20Logger%20Card)
- [`robot component: Ardupilot`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20Ardupilot)
- [`robot component: DDS`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20DDS)
- [`robot component: Others`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20Others)
- [`robot component: ABB IRC5 OPC Server`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20IRC5%20OPC%20Server)
- [`robot component: ABB Robot Communications Runtime`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20Robot%20Communications%20Runtime)
- [`robot component: ABB PC SDK`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20PC%20SDK)
- [`robot component: Dynamixel`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20Dynamixel)
- [`robot component: ABB DataManager`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20DataManager)
- [`robot component: MAVLink`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20MAVLink)
- [`robot component: ABB RobotStudio S4`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20RobotStudio%20S4)
- [`robot component: ROS`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ROS)
- [`robot component: ABB S4 OPC Server`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20S4%20OPC%20Server)
- [`robot component: ABB VSN300 WiFi`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20VSN300%20WiFi)
- [`robot component: ROS2`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ROS2)
- [`robot component: Visual Components`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20Visual%20Components)
- [`robot component: ABB CP635 HMI`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20CP635%20HMI)
- [`robot component: shadow-robot`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20shadow-robot)
- [`robot component: kobuki`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20kobuki)
- [`robot component: FastRTPS`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20FastRTPS)
- [`robot component: ABB WebWare SDK`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20WebWare%20SDK)
- [`robot component: CMS-770`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20CMS-770)
- [`robot component: ABB Test Signal Viewer 1.5`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20Test%20Signal%20Viewer%201.5)
- [`robot component: IRB140's flex pendant`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20IRB140's%20flex%20pendant)
- [`robot component: paparazzi`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20paparazzi)
- [`robot component: KUKA KR C4`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20KUKA%20KR%20C4)
- [`robot component: PX4`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20PX4)
- [`robot component: ABB QuickTeach`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20QuickTeach)
- [`robot component: navigation2`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20navigation2)
- [`robot component: Alpha 1S android application`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20Alpha%201S%20android%20application)
- [`robot component: V-Sido OS`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20V-Sido%20OS)
- [`robot component: moveit2`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20moveit2)
- [`robot component: Ubuntu`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20Ubuntu)
- [`robot component: Universal Robots Controller`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20Universal%20Robots%20Controller)
- [`robot component: ABB PickMaster 3`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20PickMaster%203)
- [`robot component: mavros`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20mavros)
- [`robot component: ABB RobotStudio`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20RobotStudio)
- [`robot component: DynamixelSDK`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20DynamixelSDK)
- [`robot component: ABB RobView 5`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20RobView%205)
- [`robot component: ABB PickMaster 5`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB%20PickMaster%205)
- [`robot component: OP2 Firmware`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20OP2%20Firmware)
- [`robot component: Sawyer Task Editor`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20Sawyer%20Task%20Editor)
- [`robot component: IRB140's main computer`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20IRB140's%20main%20computer)
- [`robot component: ABB's Service Box`](https://github.com/aliasrobotics/RVD/labels/robot%20component%3A%20ABB's%20Service%20Box)
</details>
<details><summary><b>Robot vulnerabilities by robot</b></summary>

- [`robot: Vgo`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20Vgo)
- [`robot: ER200`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20ER200)
- [`robot: MiR250`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20MiR250)
- [`robot: Sawyer`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20Sawyer)
- [`robot: MARA`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20MARA)
- [`robot: xArm6`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20xArm6)
- [`robot: care-o-bot`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20care-o-bot)
- [`robot: KUKA KR 3 R540`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20KUKA%20KR%203%20R540)
- [`robot: Parrot ANAFI`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20Parrot%20ANAFI)
- [`robot: UVD`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20UVD)
- [`robot: DBPOWER U818A`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20DBPOWER%20U818A)
- [`robot: Pepper`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20Pepper)
- [`robot: UR10`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20UR10)
- [`robot: xArm5 Lite`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20xArm5%20Lite)
- [`robot: Baxter`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20Baxter)
- [`robot: ABB IRB140`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20ABB%20IRB140)
- [`robot: xArm7`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20xArm7)
- [`robot: MiR100`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20MiR100)
- [`robot: ER-Lite`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20ER-Lite)
- [`robot: NAO`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20NAO)
- [`robot: Alpha 2`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20Alpha%202)
- [`robot: Spykee`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20Spykee)
- [`robot: UR5`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20UR5)
- [`robot: Rovio`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20Rovio)
- [`robot: MiR500`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20MiR500)
- [`robot: ER-Flex`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20ER-Flex)
- [`robot: UR3`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20UR3)
- [`robot: Alpha 1S`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20Alpha%201S)
- [`robot: ER-One`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20ER-One)
- [`robot: turtlebot`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20turtlebot)
- [`robot: MiR1000`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20MiR1000)
- [`robot: SDA10f`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20SDA10f)
- [`robot: Raven 2`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20Raven%202)
- [`robot: ROS (Jade and before)`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20ROS%20(Jade%20and%20before))
- [`robot: REEM-C`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20REEM-C)
- [`robot: MiR200`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20MiR200)
- [`robot: ER1000`](https://github.com/aliasrobotics/RVD/labels/robot%3A%20ER1000)
</details>
<details><summary><b>Robot vulnerabilities by vendor</b></summary>

- [`vendor: Rethink Robotics`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Rethink%20Robotics)
- [`vendor: Universal Robots`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Universal%20Robots)
- [`vendor: Robotis`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Robotis)
- [`vendor: WowWee`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20WowWee)
- [`vendor: DBPOWER`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20DBPOWER)
- [`vendor: Intel`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Intel)
- [`vendor: Fanuc`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Fanuc)
- [`vendor: eProsima`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20eProsima)
- [`vendor: Robotiq`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Robotiq)
- [`vendor: Mobile Industrial Robots`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Mobile%20Industrial%20Robots)
- [`vendor: Acutronic Robotics`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Acutronic%20Robotics)
- [`vendor: Open Robotics`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Open%20Robotics)
- [`vendor: Staübli`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Staübli)
- [`vendor: KUKA`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20KUKA)
- [`vendor: UVD Robots`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20UVD%20Robots)
- [`vendor: RTI`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20RTI)
- [`vendor: ADLINK`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20ADLINK)
- [`vendor: Enabled Robotics`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Enabled%20Robotics)
- [`vendor: UFactory`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20UFactory)
- [`vendor: WindRiver`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20WindRiver)
- [`vendor: Mitsubishi Electric`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Mitsubishi%20Electric)
- [`vendor: Robotemi Global`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Robotemi%20Global)
- [`vendor: Canonical`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Canonical)
- [`vendor: Applied Dexterity`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Applied%20Dexterity)
- [`vendor: Robotplus`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Robotplus)
- [`vendor: Vecna`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Vecna)
- [`vendor: ABB`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20ABB)
- [`vendor: UBTech Robotics`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20UBTech%20Robotics)
- [`vendor: Yaskawa Motoman`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Yaskawa%20Motoman)
- [`vendor: Parrot`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Parrot)
- [`vendor: PAL Robotics`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20PAL%20Robotics)
- [`vendor: Visual Components`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Visual%20Components)
- [`vendor: Softbank Robotics`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Softbank%20Robotics)
- [`vendor: Easy Robotics`](https://github.com/aliasrobotics/RVD/labels/vendor%3A%20Easy%20Robotics)
</details>


For more, visit the [complete list](https://github.com/aliasrobotics/RVDP/issues?utf8=%E2%9C%93&q=is%3Aissue+is%3Aopen+-label%3A%22invalid%22+) of reported robot vulnerabilities.


## ToC

- [ToC](#toc)
- [Concepts](#concepts)
- [Sponsored and funded projects](#sponsored-and-funded-projects)
	- [ROS 2](#ros-2)
		- [ROS 2 flaws by package (only `open` ones)](#ros-2-flaws-by-package-only-open-ones)
- [Disclosure policy](#disclosure-policy)
- [CI/CD setup](#cicd-setup)
- [Contributing, reporting a vulnerability](#contributing-reporting-a-vulnerability)
- [Contact us or send feedback](#contact-us-or-send-feedback)
	- [Automatic pings for manufacturers](#automatic-pings-for-manufacturers)
- [Appendices](#appendices)
	- [Appendix A: Vulnerabilities, bugs, bugs and more](#appendix-a-vulnerabilities-weaknesses-bugs-and-more)
		- [Research on terminology](#research-on-terminology)
		- [Discussion and interpretation](#discussion-and-interpretation)
	- [Appendix B: How does RVD relate to CVE, the CVE List and the NVD?](#appendix-b-how-does-rvd-relate-to-cve-the-cve-list-and-the-nvd)
    - [Appendix C: Legal disclaimer](#appendix-c-legal-disclaimer)

## Concepts
Each RVD issue (ticket) corresponds with a flaw that is labeled appropriately. The meaning of the most relevant labels or statuses is covered below. Refer to the appendices for definitions on the terminology used:
- [![](https://img.shields.io/badge/open-green.svg?style=flat)](https://github.com/aliasrobotics/RVD/issues): Flaw that remains active or under research.
- [![](https://img.shields.io/badge/closed-red.svg?style=flat)](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aclosed): Flaw that is inactive. Reasons for inactivity relate to mitigations, duplicates, erroneous reports or similar.
- [![](https://img.shields.io/badge/invalid-red.svg?style=flat)](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+label%3Ainvalid+): Ticket discarded and removed for the overall count. This label flags invalid or failed reports including tests and related.
- [![](https://img.shields.io/badge/duplicate-cfd3d7.svg?style=flat)](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+label%3Aduplicate+): Duplicated flaw. Might go in combination with `invalid` but if not, typically, a link to the original ticket is provided.
- [![](https://img.shields.io/badge/malformed-440fa8.svg?style=flat)](https://github.com/aliasrobotics/RVD/labels/malformed): Flaw has a malformed syntax. Refer to the templates for basic guidelines on the right syntax.
- [![](https://img.shields.io/badge/mitigated-aaf9a7.svg?style=flat)](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+label%3Amitigated+): Mitigated. A link to the corresponding mitigation is required.
- [![](https://img.shields.io/badge/quality-ddb140.svg?style=flat)](https://github.com/aliasrobotics/RVD/issues?q=label%3Aquality): Indicates that the bug is a quality one instead of a security flaw.
- [![](https://img.shields.io/badge/exposure-ccfc2d.svg?style=flat)](https://github.com/aliasrobotics/RVD/labels/exposure): Indicates that flaw is an exposure.
- [![](https://img.shields.io/badge/bug-dbf9a2.svg?style=flat)](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+label%3Abug+): Indicates that flaw is a bug, a security bug can potentially lead to a vulnerability (*Note that this last part corresponds with the definition of a `weakness`, a bug that may have security implications. However, in an attempt to simplify and for coherence with other databases, bug and weakness terms are used interchangeably*).
- [![](https://img.shields.io/badge/vulnerability-7fe0bb.svg?style=flat)](https://github.com/aliasrobotics/RVD/issues?q=is%3Aissue+is%3Aopen+label%3Avulnerability): Indicates that flaw is a vulnerability.

For more including the categorization used for flaws refer to RVD's [taxonomy](docs/TAXONOMY.md)

## Sponsored and funded projects
### ROS
*Last updated Sun, 30 May 2021 06:48:42 GMT*

|       | Open      | Closed  |    All |
|-------|---------|--------|-----------|
| `ROS` Vulnerabilities | [![label: vulns_open_ros][~vulns_open_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+) | [![label: vulns_closed_ros][~vulns_closed_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+) | [![label: vulns_ros][~vulns_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+) |
| `ROS` Bugs | [![label: bugs_open_ros][~bugs_open_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Abug+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+) | [![label: bugs_closed_ros][~bugs_closed_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+label%3Abug+-label%3A%22invalid%22+label%3A%22robot+component%3A+ROS%22+-label%3A%22duplicate%22+) | [![label: bugs_ros][~bugs_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+label%3Abug+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+) |
| `ROS` Others | [![label: others_open_ros][~others_open_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Abug+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+) | [![label: others_closed_ros][~others_closed_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+-label%3Abug+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+)  | [![label: others_ros][~others_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+-label%3Abug+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+) |


|       |       |           |          |          |
|-------|---------|---------|----------|----------|
| Severity of `ROS` Vulnerabilities (open and if available) | [![label: vulns_critical_ros][~vulns_critical_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+) | [![label: vulns_high_ros][~vulns_high_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+) | [![label: vulns_medium_ros][~vulns_medium_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+) | [![label: vulns_low_ros][~vulns_low_ros]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+label%3A%22robot%20component%3A%20ROS%22+-label%3A%22duplicate%22+) |


[~vulns_ros]: https://img.shields.io/badge/ros_vulnerabilities-9-7fe0bb.svg
[~vulns_open_ros]: https://img.shields.io/badge/ros_vulnerabilities-5-red.svg
[~vulns_closed_ros]: https://img.shields.io/badge/ros_vulnerabilities-4-green.svg
[~bugs_ros]: https://img.shields.io/badge/ros_bugs-580-dbf9a2.svg
[~bugs_open_ros]: https://img.shields.io/badge/ros_bugs-0-red.svg
[~bugs_closed_ros]: https://img.shields.io/badge/ros_bugs-580-green.svg
[~others_ros]: https://img.shields.io/badge/ros_others-0-dbf9a2.svg
[~others_open_ros]: https://img.shields.io/badge/ros_others-0-red.svg
[~others_closed_ros]: https://img.shields.io/badge/ros_others-0-green.svg
[~vulns_critical_ros]: https://img.shields.io/badge/ros_vuln.critical-2-ce5b50.svg
[~vulns_high_ros]: https://img.shields.io/badge/ros_vuln.high-2-e99695.svg
[~vulns_medium_ros]: https://img.shields.io/badge/ros_vuln.medium-1-e9cd95.svg
[~vulns_low_ros]: https://img.shields.io/badge/ros_vuln.low-0-e9e895.svg


### ROS 2
*Last updated Sun, 30 May 2021 06:48:42 GMT*

|       | Open      | Closed  |    All |
|-------|---------|--------|-----------|
| `ROS 2` Vulnerabilities | [![label: vulns_open_ros2][~vulns_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+) | [![label: vulns_closed_ros2][~vulns_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+) | [![label: vulns_ros2][~vulns_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+) |
| `ROS 2` Bugs | [![label: bugs_open_ros2][~bugs_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+label%3Abug+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+) | [![label: bugs_closed_ros2][~bugs_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+label%3Abug+-label%3A%22invalid%22+label%3A%22robot+component%3A+ROS2%22+-label%3A%22duplicate%22+) | [![label: bugs_ros2][~bugs_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+label%3Abug+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+) |
| `ROS 2` Others | [![label: others_open_ros2][~others_open_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3Abug+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+) | [![label: others_closed_ros2][~others_closed_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aclosed+-label%3Abug+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+)  | [![label: others_ros2][~others_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aall+-label%3Abug+-label%3Avulnerability+-label%3A%22invalid%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+) |


|       |       |           |          |          |
|-------|---------|---------|----------|----------|
| Severity of `ROS 2` Vulnerabilities (open and if available) | [![label: vulns_critical_ros2][~vulns_critical_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+critical%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+) | [![label: vulns_high_ros2][~vulns_high_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+high%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+) | [![label: vulns_medium_ros2][~vulns_medium_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+medium%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+) | [![label: vulns_low_ros2][~vulns_low_ros2]](https://github.com/aliasrobotics/RVD/issues?utf8=%E2%9C%93&q=is%3Aopen+-label%3A%22invalid%22+label%3A%22severity%3A+low%22+label%3A%22robot%20component%3A%20ROS2%22+-label%3A%22duplicate%22+) |


[~vulns_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-8-7fe0bb.svg
[~vulns_open_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-8-red.svg
[~vulns_closed_ros2]: https://img.shields.io/badge/ros2_vulnerabilities-0-green.svg
[~bugs_ros2]: https://img.shields.io/badge/ros2_bugs-254-dbf9a2.svg
[~bugs_open_ros2]: https://img.shields.io/badge/ros2_bugs-0-red.svg
[~bugs_closed_ros2]: https://img.shields.io/badge/ros2_bugs-254-green.svg
[~others_ros2]: https://img.shields.io/badge/ros2_others-0-dbf9a2.svg
[~others_open_ros2]: https://img.shields.io/badge/ros2_others-0-red.svg
[~others_closed_ros2]: https://img.shields.io/badge/ros2_others-0-green.svg
[~vulns_critical_ros2]: https://img.shields.io/badge/ros2_vuln.critical-0-ce5b50.svg
[~vulns_high_ros2]: https://img.shields.io/badge/ros2_vuln.high-0-e99695.svg
[~vulns_medium_ros2]: https://img.shields.io/badge/ros2_vuln.medium-2-e9cd95.svg
[~vulns_low_ros2]: https://img.shields.io/badge/ros2_vuln.low-0-e9e895.svg





## Disclosure policy

*Together with RVD, we propose a coherent diclosure policy adopted first by Alias Robotics. Thee disclosure policy is highly inspired by [Google's Project Zero](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-faq.html). TL;DR, unless otherwise specified, we adhere to a 90-day disclosure deadline for new vulnerabilities*.

*This policy is strongly in line with our desire to improve the robotics industry response times to security bugs, but also results in softer landings for bugs marginally over deadline. According to [our research](https://arxiv.org/pdf/1806.06681.pdf), most vendors are ignoring security flaws completely. We call on all researchers to adopt disclosure deadlines in some form, and feel free to use our policy verbatim (we've actually done so, from [Google's](https://www.google.com/about/appsecurity/)) if you find our record and reasoning compelling. Creating pressure towards more reasonably-timed fixes will result in smaller windows of opportunity for blackhats to abuse vulnerabilities. Given the direct physical connection with the world that robots have,  in our opinion, vulnerability disclosure policies such as ours result in greater security in robotics and an overall improved safety. A security-first approach is a must to ensure safe robotic operations.*

The maintainers of RVD believe that vulnerability disclosure is a two-way street where both vendors and researchers, must act responsibly.  We generally adhere to a **90-day disclosure deadline for new vulnerabilities** while other flaws such as simple bugs or bugs could be filed at any point in time (refer to [Appendix A](#appendix-a-vulnerabilities-bugs-bugs-and-more) for the difference between vulnerabilities, bugs and bugs). We notify vendors of vulnerabilities immediately, with **details shared in public with the defensive community after 90 days**, or sooner if the vendor releases a fix.

Similar to Google's policy, we want to acknowledge that the deadline can vary in the following ways:
- If a deadline is due to expire on a weekend or public holiday, the deadline will be moved to the next normal work day.

- Before the 90-day deadline has expired, if a vendor lets us know that a patch is scheduled for release on a specific day that will fall within 14 days following the deadline, we will delay the public disclosure until the availability of the patch.

- When we observe a previously unknown and unpatched vulnerability in software under active exploitation (a “0day”), we believe that more urgent action—within 7 days—is appropriate. The reason for this special designation is that each day an actively exploited vulnerability remains undisclosed to the public and unpatched, more devices or accounts will be compromised. Seven days is an aggressive timeline and may be too short for some vendors to update their products, but it should be enough time to publish advice about possible mitigations, such as temporarily disabling a service, restricting access, or contacting the vendor for more information. As a result, after 7 days have elapsed without a patch or advisory, we will support researchers making details available so that users can take steps to protect themselves.

Each security researcher or group should reserve the right to bring deadlines forwards or backwards based on extreme circumstances. We remain committed to treating all vendors strictly equally and we expect to be held to the same standard.

## CI/CD setup
In an attempt to lower the overall effort to maintain the Robot Vulnerability Database, RVD attempts to make active use of Continuous Integration (CI) and Continuous Deployment (CD) techniques through Github Actions. See our [configurations here](.github/workflows). Contributions and new ideas to this section are welcome. Please submit a Pull Request with your proposal or enhancement.

Below we list some of the existing capabilities (some **deprecated** in the current setup) and some tentative ones for future versions:

#### **Beta** (>= `0.5`)
- [x] Comparison of stack trace before flaw submission to avoid duplicates (perfomed upstream) [**deprecated**, modern versions of the database include more information of relevance than solely the stack trace on each ticket]
- [x] Markdown parser that conforms with RVD templates [**deprecated**, moved to YAML format]
- [x] Automatic flaw-syntax evaluation (based on parser), tags tickets as `malformed` when applicable [**deprecated**, syntax changed]
- [x] Automatic feedback on flaw-syntax, introduced in tickets directly as a comment [**deprecated**, syntax changed]

#### **1.x** (>= `1.0`)
- [x] Discussion on a more formal taxonomy to apply when categorizing flaws (see [docs/TAXONOMY.md](docs/TAXONOMY.md))
- [x] Definition of a formal schema for RVD coherent to the taxonomy and inspired by prior work
- [x] Automatic re-generation of README.md as summary
- [x] Development of CLI toolset to manage RVD
- [x] Include ID in the title of the ticket as "RVD#ID: ..."
- [x] Automatic review of database in-search for duplicates
- [ ] Automatic review of database in-search for malformed tickets, tag them appropriately
    - [ ] Automatic feedback on malformations
    - [ ] Notify when ticket is malformed and skip it (instead of throwing an error as of now)
    - [ ] Consider restrictions on title ("RVD#ID: ...")
- [x] Unify YAML dumps in tickets (e.g. stick to yaml.dump(yaml_document))
- [x] Extend TAXONOMY and language to include 'exploitation-recipe'
- [ ] Extend TAXONOMY and language to include product and versions, to simplify CVE submission
- [ ] Match both Github labels and YAML fields for selected topics:
    - [ ] Vendor/manufacturer
    - [ ] Products affected
- [ ] Use local cache of tickets for all verbs, instead of polling from database every time
- [x] Develop capabilities to output CVE JSON-compatible tickets
- [ ] Security action: Add a first-step towards a security pipeline that performs static analysis on source code

#### Future
- [ ] Security action: Unit, functional and integration tests
- [ ] Security action: other (TODO: dep. tracking, dynamic analysis)
- [ ] Make a table with versions per product and automatically-mitigate (and close) flaws in older versions that haven't been (auto)detected in newer versions.
- [ ] Automatic and periodic review of security advisories "in search" for robot-related vulnerabilities
- [ ] Automatic and periodic review of NVD "in search" for robot-related vulnerabilities
- [ ] Automatic and periodic review of CVE List "in search" for robot-related vulnerabilities
- [ ] CWE ID parser and validation method to conform with official CWE guidelines
- [ ] Automatic CWE ID validation mechanism (and feedback) in all tickets. Upgrade flaw-syntax evaluation.
- [ ] RVSS parser and validation to conform with RVSSv1.0 spec.
- [ ] Define some temporal limits for tickets, if it remains without updates longer than the limit, close automatically
  - [ ] Consider closed issues when checking for duplicates and if collisions appear, re-open and indicate so
- [ ] Automatic RVSS validation mechanism (and feedback) in all tickets. Upgrade flaw-syntax evaluation.
- [ ] schema
    - [ ] enforce `subsystem` policy
    - [ ] enforce `id` policy
    - [ ] `architectural-location` get consistency between `platform code` and `platform-code`. Same for `application-specific`. Also, remove `ROS-specific`.
    - [ ] `specificity`, enfoce policy and allowed keywords

## Contributing, reporting a vulnerability

Vulnerabilities are community-contributed. If you believe you have discovered a vulnerability in a robot or robot component (either software or hardware), obtain public acknowledgement by submitting a vulnerability while providing prove of it. Reports can be submitted in the form of [an issue](https://github.com/aliasrobotics/RVDP/issues/new?template=vulnerability-template.md).

If you wish to contribute to the RVD repository's content, please note that this document (`README.md`) is generated automatically. Submit the corresponding PRs by looking at the `rvd_tools/` folder. If you need some inspiration or ideas to contribute, refer to [CI/CD setup](#ci/cd-setup).


## Contact us or send feedback

Feel free to contact us if you have any requests of feedaback at **contact[at]aliasrobotics[dot]com**

### Automatic pings for manufacturers
By default, new vulnerabilities are reported to manufacturers and/or open source projects however other flaws aren't. Alias Robotics can inform manufacturers directly when bugs are reported. If you're interested in this service, contact **contact[at]aliasrobotics[dot]com**.

### Cite our work

```
@article{vilches2019introducing,
  title={Introducing the robot vulnerability database (rvd)},
  author={Mayoral-Vilches, V{'\i}ctor and Juan, Lander Usategui San and Dieber, Bernhard and Carbajo, Unai Ayucar and Gil-Uriarte, Endika},
  journal={arXiv preprint arXiv:1912.11299},
  year={2019}
}

```

## Appendices

### Appendix A: Vulnerabilities, weaknesses, bugs and more
#### Research on terminology
[Commonly](https://en.wikipedia.org/wiki/Software_bug):
- A **software `bug`** is an error, flaw, failure or fault in a computer program or system that causes it to produce an incorrect or unexpected result, or to behave in unintended ways.

According to [CWE](https://cwe.mitre.org/about/faq.html#A.2):
- **software `weaknesses`** are errors (bugs) that can lead to software vulnerabilities.
- **software `vulnerability`** is a mistake in software that can be directly used by a hacker to gain access to a system or network.

Moreover, according to [CVE page](https://cve.mitre.org/about/faqs.html#what_is_vulnerability):
- A `vulnerability` is a `bug` in the computational logic (e.g., code) found in software and some hardware components (e.g., firmware) that, when exploited, results in a negative impact to confidentiality, integrity or availability (more [here](https://cve.mitre.org/about/terminology.html)).
- An `exposure` is a system configuration issue or a mistake in software that allows access to information or capabilities that can be used by a hacker as a stepping-stone into a system or network.

[ISO/IEC 27001](https://www.iso.org/isoiec-27001-information-security.html) defines only vulnerability:
- **(robot) vulnerability**: bug of an asset or control that can be exploited by one or more threats

#### Discussion and interpretation

From the definitions above, it seems reasonable to associate use interchangeably `bugs` and `flaws` when referring to software issues.
In addition, the word `weakness` seems applicable to any flaw that might turn into a `vulnerability` however it must be noted that
(from the text above) a `vulnerability` "must be exploited"). Based on this a clear difference can be established classifiying
flaws with no potential to be exploitable as `bugs` and flaws potentially exploitable as `vulnerabilities`. Ortogonal to this appear
`exposures` which refer to misconfigurations that allows attackers to establish an attack vector in a system.

Beyond pure logic, an additional piece of information that comes out of researching other security databases
is that most security-oriented databases do not distinguish between bugs (general bugs) and weaknesses (security bugs).

Based in all of the above, we interpret and make the following assumptions for RVD:
- unless specified, all `flaws` are "security flaws" (an alternative could be a quality flaw)
- `flaw`, `bug` and `weakness` refer to the same thing and can be used interchangeably
- a `bug` is a flaw with potential to be exploited (but unconfirmed exploitability) unless specified with the `quality` label in which case, refers to a general non security-related bug.
- `vulnerability` is a bug that is exploitable.
- `exposure` is a configuration error or mistake in software that *without leading to exploitation*, leaks relevant information that empowers an attacker.

### Appendix B: How does RVD relate to CVE, the CVE List and the NVD?

Some definitions:
- `Robot Vulnerability Database (RVD)` is a database for robot vulnerabilities and bugs that aims to record and categorize flaws that apply to robot and robot components. RVD was created as a community-contributed and open archive of robot security flaws. It was originally created and sponsored by Alias Robotics.
- `Common Vulnerabilities and Exposures (CVE)` List CVE® is an archive (dictionary according to the official source) of entries—each containing an identification number, a description, and at least one public reference—for publicly known cybersecurity vulnerabilities. CVE contains vulnerabilities and exposures and is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security Agency (CISA). It is **not** a database (see [official information](https://cve.mitre.org/about/faqs.html)). CVE List *feeds* vulnerability databases (such as the National Vulnerability Database (NVD)) with its entries and also acts as an aggregator of vulnerabilities and exposures reported at NVD.
- `U.S. National Vulnerability Database (NVD)` is the U.S. government repository of standards based vulnerability management data. It presents an archive with vulnerabilities, each with their corresponding CVE identifiers. NVD gets fed by the CVE List and then builds upon the information included in CVE Entries to provide enhanced information for each entry such as fix information, severity scores, and impact ratings.

RVD does **not** aim to replace CVE but to <ins>complement it for the domain of robotics</ins>. RVD aims to become CVE-compatible (see [official guidelines for compatibility](https://cve.mitre.org/compatible/guidelines.html)) by tackling aspects such scope and impact of the flaws (through a proper severity scoring mechanism for robots), information for facilitating mitigation, detailed technical information, etc. For a more detailed discussion, see [this ROS Discourse thread](https://discourse.ros.org/t/introducing-the-robot-vulnerability-database/11105/7?u=vmayoral).

When compared to other vulnerability databases, RVD aims to differenciate itself by focusing on the following:
- **robot specific**: RVD aims to focus and capture robot-specific flaws. If a flaw does not end-up applying to a robot or a robot component then it should not be recorded here.
- **community-oriented**: while RVD is originally sponsored by Alias Robotics, it aims to become community-managed and contributed.
- **facilitates reproducing robot flaws**: Working with robots is very time consuming. Mitigating a vulnerability or a bug requires one to first reproduce the flaw. This can be extremely time consuming. Not so much providing the fix itself but ensuring that your environment is appropriate. At RVD, each flaw entry should aim to include a field named as `reproduction-image`. This should correspond with the link to a Docker image that should allow anyone reproduce the flaw easily.
- **robot-specific severity scoring**: opposed to CVSS which has strong limitations when applied to robotics, RVD uses RVSS, a robot-specific scoring mechanism.

As part of RVD, we encourage security researchers to file CVE Entries and use official CVE identifiers for their reports and discussions at RVD.


### Appendix C: Legal disclaimer

*ACCESS TO THIS DATABASE (OR PORTIONS THEREOF) AND THE USE OF INFORMATION, MATERIALS, PRODUCTS
OR SERVICES PROVIDED THROUGH THIS WEB SITE (OR PORTIONS THEREOF), IS NOT INTENDED, AND
IS PROHIBITED, WHERE SUCH ACCESS OR USE VIOLATES APPLICABLE LAWS OR REGULATIONS.*

*By using or accessing this database you warrant to Alias Robotics S.L. that you will
not use this Web site for any purpose that is unlawful or that is prohibited. This product
is provided with "no warranties, either express or implied." The information contained is
provided "as-is", with "no guarantee of merchantability. In no event will Alias Robotics S.L.
be liable for any incidental, indirect, consequential, punitive or special damages of any kind,
 or any other damages whatsoever, including, without limitation, those resulting from loss of
 profit, loss of contracts, loss of reputation, goodwill, data, information, income, anticipated
 savings or business relationships, whether or not Alias Robotics S.L. has been advised of the
 possibility of such damage, arising out of or in connection with the use of this database or
 any linked websites."*


 These Terms of Use are made under Spanish law and this database is operated from Vitoria-Gasteiz, Spain.
 Access to, or use of, this database site or information, materials, products and/or services
 on this site may be prohibited by law in certain countries or jurisdictions. You are responsible for
 compliance with any applicable laws of the country from which you are accessing this site.
 We make no representation that the information contained herein is appropriate or available
  for use in any location.

You agree that the courts of Vitoria-Gasteiz, Spain shall have exclusive jurisdiction to
resolve any controversy or claim of whatever nature arising out of or relating to use of
this site. However, we retain the right to bring legal proceedings in any jurisdiction
where we believe that infringement of this agreement is taking place or originating.


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

