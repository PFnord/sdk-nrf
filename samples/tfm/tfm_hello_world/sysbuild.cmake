#
# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

# Apply the shared bootloaders partition layout to the mcuboot and b0 images
# for the FILE_SUFFIX=bootloaders variant on nRF5340. The application image
# picks the same layout up through its board overlay
# (boards/nrf5340dk_nrf5340_cpuapp_ns_bootloaders.overlay), which #includes
# the same .dtsi. Other SoC series in this sample stay on Partition Manager
# and are unaffected.
if(SB_CONFIG_SOC_NRF5340_CPUAPP)
  set(partitions_overlay
      ${APP_DIR}/sysbuild/nrf5340_bootloaders_partitions.dtsi)

  if(TARGET mcuboot)
    add_overlay_dts(mcuboot ${partitions_overlay})
  endif()

  if(TARGET b0)
    add_overlay_dts(b0 ${partitions_overlay})
  endif()
endif()
