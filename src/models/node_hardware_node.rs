/* 
 * Isilon SDK
 *
 * Isilon SDK - Language bindings for the OneFS API
 *
 * OpenAPI spec version: 5
 * Contact: sdk@isilon.com
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */


#[allow(unused_imports)]
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeHardwareNode {
  /// Name of this node's chassis.
  #[serde(rename = "chassis")]
  chassis: Option<String>,
  /// Chassis code of this node (1U, 2U, etc.).
  #[serde(rename = "chassis_code")]
  chassis_code: Option<String>,
  /// Number of chassis making up this node.
  #[serde(rename = "chassis_count")]
  chassis_count: Option<String>,
  /// Chassis depth for this node if applicable (Normal, Deep, Unknown). If not supported: Unknown. If Logic to determine chassis depth fails: Unknown. If PSI_Get fails: Unknown. PSI_Get can fail if PSI not initialized, or key does not exist.
  #[serde(rename = "chassis_depth")]
  chassis_depth: Option<String>,
  /// Class of this node (storage, accelerator, etc.).
  #[serde(rename = "class")]
  class: Option<String>,
  /// Code name of this node if applicable (Minnetonka, MiniHuron, Huron, Union, Tahoe, Superior, Unknown). If not supported: Unknown. If Logic to determine code name fails: Unknown. If PSI_Get fails: Unknown. PSI_Get can fail if PSI not initialized, or key does not exist.
  #[serde(rename = "code_name")]
  code_name: Option<String>,
  /// Type of compute node if applicable (Low, Medium, High, Turbo, Ultra, Unknown). If not supported: Unknown. If Logic to determine compute type fails: Unknown. If PSI_Get fails: Unknown. PSI_Get can fail if PSI not initialized, or key does not exist.
  #[serde(rename = "compute_type")]
  compute_type: Option<String>,
  /// Node configuration ID.
  #[serde(rename = "configuration_id")]
  configuration_id: Option<String>,
  /// Manufacturer and model of this node's CPU.
  #[serde(rename = "cpu")]
  cpu: Option<String>,
  /// Manufacturer and model of this node's disk controller.
  #[serde(rename = "disk_controller")]
  disk_controller: Option<String>,
  /// Manufacturer and model of this node's disk expander.
  #[serde(rename = "disk_expander")]
  disk_expander: Option<String>,
  /// Family code of this node (X, S, NL, etc.).
  #[serde(rename = "family_code")]
  family_code: Option<String>,
  /// Manufacturer, model, and device id of this node's flash drive.
  #[serde(rename = "flash_drive")]
  flash_drive: Option<String>,
  /// Generation code of this node.
  #[serde(rename = "generation_code")]
  generation_code: Option<String>,
  /// Isilon hardware generation name.
  #[serde(rename = "hwgen")]
  hwgen: Option<String>,
  /// Node ID (Device Number) of this node.
  #[serde(rename = "id")]
  id: Option<i32>,
  /// Version of this node's Isilon Management Board.
  #[serde(rename = "imb_version")]
  imb_version: Option<String>,
  /// Infiniband card type.
  #[serde(rename = "infiniband")]
  infiniband: Option<String>,
  /// Version of the LCD panel.
  #[serde(rename = "lcd_version")]
  lcd_version: Option<String>,
  /// Logical Node Number (LNN) of this node.
  #[serde(rename = "lnn")]
  lnn: Option<i32>,
  /// Isilon node model identifier string (S200, X410, Infinity-H500, etc.).
  #[serde(rename = "model")]
  model: Option<String>,
  /// Isilon node model code string (S200, X410, H500, etc.).
  #[serde(rename = "model_code")]
  model_code: Option<String>,
  /// Manufacturer and model of this node's motherboard.
  #[serde(rename = "motherboard")]
  motherboard: Option<String>,
  /// Description of all this node's network interfaces.
  #[serde(rename = "net_interfaces")]
  net_interfaces: Option<String>,
  /// Position of node within chassis (e.g., 1-4 for Infinity chassis). -1 for error or not supported.
  #[serde(rename = "node_slot_id")]
  node_slot_id: Option<i32>,
  /// Manufacturer and model of this node's NVRAM board.
  #[serde(rename = "nvram")]
  nvram: Option<String>,
  /// Serial number of this node's peer/buddy node.(Infinity Only)
  #[serde(rename = "peer_serial_number")]
  peer_serial_number: Option<String>,
  /// Performance code of this node, if applicable (2, 4, 5, etc.).
  #[serde(rename = "performance_code")]
  performance_code: Option<String>,
  /// Description strings for each power supply on this node.
  #[serde(rename = "powersupplies")]
  powersupplies: Option<Vec<String>>,
  /// Number of processors and cores on this node.
  #[serde(rename = "processor")]
  processor: Option<String>,
  /// Isilon product name.
  #[serde(rename = "product")]
  product: Option<String>,
  /// Size of RAM in bytes.
  #[serde(rename = "ram")]
  ram: Option<i32>,
  /// Serial number of this node.
  #[serde(rename = "serial_number")]
  serial_number: Option<String>,
  /// Series of this node (X, I, NL, etc.).
  #[serde(rename = "series")]
  series: Option<String>,
  /// Size of drive sleds in node, if applicable. Expected values: 3, 4, 6. 0 if unable to determine sled size. -1 for error or not supported. If PSI_Get fails: -1. PSI_Get can fail if PSI not initialized, or key does not exist.
  #[serde(rename = "sled_drive_count")]
  sled_drive_count: Option<i32>,
  /// Storage class of this node (storage or diskless).
  #[serde(rename = "storage_class")]
  storage_class: Option<String>,
  /// Platform tier level of this node if applicable (1-4 are defined, 0 for unknown or not supported, -1 for error). If not supported: 0. If Logic to determine tier fails: 0 for unknown. If PSI_Get fails: -1 for error. PSI_Get can fail if PSI not initialized, or key does not exist.
  #[serde(rename = "tier")]
  tier: Option<i32>,
  /// Serial number of the top level assembly of this node.(Infinity Only)
  #[serde(rename = "top_level_assembly_serial_number")]
  top_level_assembly_serial_number: String
}

impl NodeHardwareNode {
  pub fn new(top_level_assembly_serial_number: String) -> NodeHardwareNode {
    NodeHardwareNode {
      chassis: None,
      chassis_code: None,
      chassis_count: None,
      chassis_depth: None,
      class: None,
      code_name: None,
      compute_type: None,
      configuration_id: None,
      cpu: None,
      disk_controller: None,
      disk_expander: None,
      family_code: None,
      flash_drive: None,
      generation_code: None,
      hwgen: None,
      id: None,
      imb_version: None,
      infiniband: None,
      lcd_version: None,
      lnn: None,
      model: None,
      model_code: None,
      motherboard: None,
      net_interfaces: None,
      node_slot_id: None,
      nvram: None,
      peer_serial_number: None,
      performance_code: None,
      powersupplies: None,
      processor: None,
      product: None,
      ram: None,
      serial_number: None,
      series: None,
      sled_drive_count: None,
      storage_class: None,
      tier: None,
      top_level_assembly_serial_number: top_level_assembly_serial_number
    }
  }

  pub fn set_chassis(&mut self, chassis: String) {
    self.chassis = Some(chassis);
  }

  pub fn with_chassis(mut self, chassis: String) -> NodeHardwareNode {
    self.chassis = Some(chassis);
    self
  }

  pub fn chassis(&self) -> Option<&String> {
    self.chassis.as_ref()
  }

  pub fn reset_chassis(&mut self) {
    self.chassis = None;
  }

  pub fn set_chassis_code(&mut self, chassis_code: String) {
    self.chassis_code = Some(chassis_code);
  }

  pub fn with_chassis_code(mut self, chassis_code: String) -> NodeHardwareNode {
    self.chassis_code = Some(chassis_code);
    self
  }

  pub fn chassis_code(&self) -> Option<&String> {
    self.chassis_code.as_ref()
  }

  pub fn reset_chassis_code(&mut self) {
    self.chassis_code = None;
  }

  pub fn set_chassis_count(&mut self, chassis_count: String) {
    self.chassis_count = Some(chassis_count);
  }

  pub fn with_chassis_count(mut self, chassis_count: String) -> NodeHardwareNode {
    self.chassis_count = Some(chassis_count);
    self
  }

  pub fn chassis_count(&self) -> Option<&String> {
    self.chassis_count.as_ref()
  }

  pub fn reset_chassis_count(&mut self) {
    self.chassis_count = None;
  }

  pub fn set_chassis_depth(&mut self, chassis_depth: String) {
    self.chassis_depth = Some(chassis_depth);
  }

  pub fn with_chassis_depth(mut self, chassis_depth: String) -> NodeHardwareNode {
    self.chassis_depth = Some(chassis_depth);
    self
  }

  pub fn chassis_depth(&self) -> Option<&String> {
    self.chassis_depth.as_ref()
  }

  pub fn reset_chassis_depth(&mut self) {
    self.chassis_depth = None;
  }

  pub fn set_class(&mut self, class: String) {
    self.class = Some(class);
  }

  pub fn with_class(mut self, class: String) -> NodeHardwareNode {
    self.class = Some(class);
    self
  }

  pub fn class(&self) -> Option<&String> {
    self.class.as_ref()
  }

  pub fn reset_class(&mut self) {
    self.class = None;
  }

  pub fn set_code_name(&mut self, code_name: String) {
    self.code_name = Some(code_name);
  }

  pub fn with_code_name(mut self, code_name: String) -> NodeHardwareNode {
    self.code_name = Some(code_name);
    self
  }

  pub fn code_name(&self) -> Option<&String> {
    self.code_name.as_ref()
  }

  pub fn reset_code_name(&mut self) {
    self.code_name = None;
  }

  pub fn set_compute_type(&mut self, compute_type: String) {
    self.compute_type = Some(compute_type);
  }

  pub fn with_compute_type(mut self, compute_type: String) -> NodeHardwareNode {
    self.compute_type = Some(compute_type);
    self
  }

  pub fn compute_type(&self) -> Option<&String> {
    self.compute_type.as_ref()
  }

  pub fn reset_compute_type(&mut self) {
    self.compute_type = None;
  }

  pub fn set_configuration_id(&mut self, configuration_id: String) {
    self.configuration_id = Some(configuration_id);
  }

  pub fn with_configuration_id(mut self, configuration_id: String) -> NodeHardwareNode {
    self.configuration_id = Some(configuration_id);
    self
  }

  pub fn configuration_id(&self) -> Option<&String> {
    self.configuration_id.as_ref()
  }

  pub fn reset_configuration_id(&mut self) {
    self.configuration_id = None;
  }

  pub fn set_cpu(&mut self, cpu: String) {
    self.cpu = Some(cpu);
  }

  pub fn with_cpu(mut self, cpu: String) -> NodeHardwareNode {
    self.cpu = Some(cpu);
    self
  }

  pub fn cpu(&self) -> Option<&String> {
    self.cpu.as_ref()
  }

  pub fn reset_cpu(&mut self) {
    self.cpu = None;
  }

  pub fn set_disk_controller(&mut self, disk_controller: String) {
    self.disk_controller = Some(disk_controller);
  }

  pub fn with_disk_controller(mut self, disk_controller: String) -> NodeHardwareNode {
    self.disk_controller = Some(disk_controller);
    self
  }

  pub fn disk_controller(&self) -> Option<&String> {
    self.disk_controller.as_ref()
  }

  pub fn reset_disk_controller(&mut self) {
    self.disk_controller = None;
  }

  pub fn set_disk_expander(&mut self, disk_expander: String) {
    self.disk_expander = Some(disk_expander);
  }

  pub fn with_disk_expander(mut self, disk_expander: String) -> NodeHardwareNode {
    self.disk_expander = Some(disk_expander);
    self
  }

  pub fn disk_expander(&self) -> Option<&String> {
    self.disk_expander.as_ref()
  }

  pub fn reset_disk_expander(&mut self) {
    self.disk_expander = None;
  }

  pub fn set_family_code(&mut self, family_code: String) {
    self.family_code = Some(family_code);
  }

  pub fn with_family_code(mut self, family_code: String) -> NodeHardwareNode {
    self.family_code = Some(family_code);
    self
  }

  pub fn family_code(&self) -> Option<&String> {
    self.family_code.as_ref()
  }

  pub fn reset_family_code(&mut self) {
    self.family_code = None;
  }

  pub fn set_flash_drive(&mut self, flash_drive: String) {
    self.flash_drive = Some(flash_drive);
  }

  pub fn with_flash_drive(mut self, flash_drive: String) -> NodeHardwareNode {
    self.flash_drive = Some(flash_drive);
    self
  }

  pub fn flash_drive(&self) -> Option<&String> {
    self.flash_drive.as_ref()
  }

  pub fn reset_flash_drive(&mut self) {
    self.flash_drive = None;
  }

  pub fn set_generation_code(&mut self, generation_code: String) {
    self.generation_code = Some(generation_code);
  }

  pub fn with_generation_code(mut self, generation_code: String) -> NodeHardwareNode {
    self.generation_code = Some(generation_code);
    self
  }

  pub fn generation_code(&self) -> Option<&String> {
    self.generation_code.as_ref()
  }

  pub fn reset_generation_code(&mut self) {
    self.generation_code = None;
  }

  pub fn set_hwgen(&mut self, hwgen: String) {
    self.hwgen = Some(hwgen);
  }

  pub fn with_hwgen(mut self, hwgen: String) -> NodeHardwareNode {
    self.hwgen = Some(hwgen);
    self
  }

  pub fn hwgen(&self) -> Option<&String> {
    self.hwgen.as_ref()
  }

  pub fn reset_hwgen(&mut self) {
    self.hwgen = None;
  }

  pub fn set_id(&mut self, id: i32) {
    self.id = Some(id);
  }

  pub fn with_id(mut self, id: i32) -> NodeHardwareNode {
    self.id = Some(id);
    self
  }

  pub fn id(&self) -> Option<&i32> {
    self.id.as_ref()
  }

  pub fn reset_id(&mut self) {
    self.id = None;
  }

  pub fn set_imb_version(&mut self, imb_version: String) {
    self.imb_version = Some(imb_version);
  }

  pub fn with_imb_version(mut self, imb_version: String) -> NodeHardwareNode {
    self.imb_version = Some(imb_version);
    self
  }

  pub fn imb_version(&self) -> Option<&String> {
    self.imb_version.as_ref()
  }

  pub fn reset_imb_version(&mut self) {
    self.imb_version = None;
  }

  pub fn set_infiniband(&mut self, infiniband: String) {
    self.infiniband = Some(infiniband);
  }

  pub fn with_infiniband(mut self, infiniband: String) -> NodeHardwareNode {
    self.infiniband = Some(infiniband);
    self
  }

  pub fn infiniband(&self) -> Option<&String> {
    self.infiniband.as_ref()
  }

  pub fn reset_infiniband(&mut self) {
    self.infiniband = None;
  }

  pub fn set_lcd_version(&mut self, lcd_version: String) {
    self.lcd_version = Some(lcd_version);
  }

  pub fn with_lcd_version(mut self, lcd_version: String) -> NodeHardwareNode {
    self.lcd_version = Some(lcd_version);
    self
  }

  pub fn lcd_version(&self) -> Option<&String> {
    self.lcd_version.as_ref()
  }

  pub fn reset_lcd_version(&mut self) {
    self.lcd_version = None;
  }

  pub fn set_lnn(&mut self, lnn: i32) {
    self.lnn = Some(lnn);
  }

  pub fn with_lnn(mut self, lnn: i32) -> NodeHardwareNode {
    self.lnn = Some(lnn);
    self
  }

  pub fn lnn(&self) -> Option<&i32> {
    self.lnn.as_ref()
  }

  pub fn reset_lnn(&mut self) {
    self.lnn = None;
  }

  pub fn set_model(&mut self, model: String) {
    self.model = Some(model);
  }

  pub fn with_model(mut self, model: String) -> NodeHardwareNode {
    self.model = Some(model);
    self
  }

  pub fn model(&self) -> Option<&String> {
    self.model.as_ref()
  }

  pub fn reset_model(&mut self) {
    self.model = None;
  }

  pub fn set_model_code(&mut self, model_code: String) {
    self.model_code = Some(model_code);
  }

  pub fn with_model_code(mut self, model_code: String) -> NodeHardwareNode {
    self.model_code = Some(model_code);
    self
  }

  pub fn model_code(&self) -> Option<&String> {
    self.model_code.as_ref()
  }

  pub fn reset_model_code(&mut self) {
    self.model_code = None;
  }

  pub fn set_motherboard(&mut self, motherboard: String) {
    self.motherboard = Some(motherboard);
  }

  pub fn with_motherboard(mut self, motherboard: String) -> NodeHardwareNode {
    self.motherboard = Some(motherboard);
    self
  }

  pub fn motherboard(&self) -> Option<&String> {
    self.motherboard.as_ref()
  }

  pub fn reset_motherboard(&mut self) {
    self.motherboard = None;
  }

  pub fn set_net_interfaces(&mut self, net_interfaces: String) {
    self.net_interfaces = Some(net_interfaces);
  }

  pub fn with_net_interfaces(mut self, net_interfaces: String) -> NodeHardwareNode {
    self.net_interfaces = Some(net_interfaces);
    self
  }

  pub fn net_interfaces(&self) -> Option<&String> {
    self.net_interfaces.as_ref()
  }

  pub fn reset_net_interfaces(&mut self) {
    self.net_interfaces = None;
  }

  pub fn set_node_slot_id(&mut self, node_slot_id: i32) {
    self.node_slot_id = Some(node_slot_id);
  }

  pub fn with_node_slot_id(mut self, node_slot_id: i32) -> NodeHardwareNode {
    self.node_slot_id = Some(node_slot_id);
    self
  }

  pub fn node_slot_id(&self) -> Option<&i32> {
    self.node_slot_id.as_ref()
  }

  pub fn reset_node_slot_id(&mut self) {
    self.node_slot_id = None;
  }

  pub fn set_nvram(&mut self, nvram: String) {
    self.nvram = Some(nvram);
  }

  pub fn with_nvram(mut self, nvram: String) -> NodeHardwareNode {
    self.nvram = Some(nvram);
    self
  }

  pub fn nvram(&self) -> Option<&String> {
    self.nvram.as_ref()
  }

  pub fn reset_nvram(&mut self) {
    self.nvram = None;
  }

  pub fn set_peer_serial_number(&mut self, peer_serial_number: String) {
    self.peer_serial_number = Some(peer_serial_number);
  }

  pub fn with_peer_serial_number(mut self, peer_serial_number: String) -> NodeHardwareNode {
    self.peer_serial_number = Some(peer_serial_number);
    self
  }

  pub fn peer_serial_number(&self) -> Option<&String> {
    self.peer_serial_number.as_ref()
  }

  pub fn reset_peer_serial_number(&mut self) {
    self.peer_serial_number = None;
  }

  pub fn set_performance_code(&mut self, performance_code: String) {
    self.performance_code = Some(performance_code);
  }

  pub fn with_performance_code(mut self, performance_code: String) -> NodeHardwareNode {
    self.performance_code = Some(performance_code);
    self
  }

  pub fn performance_code(&self) -> Option<&String> {
    self.performance_code.as_ref()
  }

  pub fn reset_performance_code(&mut self) {
    self.performance_code = None;
  }

  pub fn set_powersupplies(&mut self, powersupplies: Vec<String>) {
    self.powersupplies = Some(powersupplies);
  }

  pub fn with_powersupplies(mut self, powersupplies: Vec<String>) -> NodeHardwareNode {
    self.powersupplies = Some(powersupplies);
    self
  }

  pub fn powersupplies(&self) -> Option<&Vec<String>> {
    self.powersupplies.as_ref()
  }

  pub fn reset_powersupplies(&mut self) {
    self.powersupplies = None;
  }

  pub fn set_processor(&mut self, processor: String) {
    self.processor = Some(processor);
  }

  pub fn with_processor(mut self, processor: String) -> NodeHardwareNode {
    self.processor = Some(processor);
    self
  }

  pub fn processor(&self) -> Option<&String> {
    self.processor.as_ref()
  }

  pub fn reset_processor(&mut self) {
    self.processor = None;
  }

  pub fn set_product(&mut self, product: String) {
    self.product = Some(product);
  }

  pub fn with_product(mut self, product: String) -> NodeHardwareNode {
    self.product = Some(product);
    self
  }

  pub fn product(&self) -> Option<&String> {
    self.product.as_ref()
  }

  pub fn reset_product(&mut self) {
    self.product = None;
  }

  pub fn set_ram(&mut self, ram: i32) {
    self.ram = Some(ram);
  }

  pub fn with_ram(mut self, ram: i32) -> NodeHardwareNode {
    self.ram = Some(ram);
    self
  }

  pub fn ram(&self) -> Option<&i32> {
    self.ram.as_ref()
  }

  pub fn reset_ram(&mut self) {
    self.ram = None;
  }

  pub fn set_serial_number(&mut self, serial_number: String) {
    self.serial_number = Some(serial_number);
  }

  pub fn with_serial_number(mut self, serial_number: String) -> NodeHardwareNode {
    self.serial_number = Some(serial_number);
    self
  }

  pub fn serial_number(&self) -> Option<&String> {
    self.serial_number.as_ref()
  }

  pub fn reset_serial_number(&mut self) {
    self.serial_number = None;
  }

  pub fn set_series(&mut self, series: String) {
    self.series = Some(series);
  }

  pub fn with_series(mut self, series: String) -> NodeHardwareNode {
    self.series = Some(series);
    self
  }

  pub fn series(&self) -> Option<&String> {
    self.series.as_ref()
  }

  pub fn reset_series(&mut self) {
    self.series = None;
  }

  pub fn set_sled_drive_count(&mut self, sled_drive_count: i32) {
    self.sled_drive_count = Some(sled_drive_count);
  }

  pub fn with_sled_drive_count(mut self, sled_drive_count: i32) -> NodeHardwareNode {
    self.sled_drive_count = Some(sled_drive_count);
    self
  }

  pub fn sled_drive_count(&self) -> Option<&i32> {
    self.sled_drive_count.as_ref()
  }

  pub fn reset_sled_drive_count(&mut self) {
    self.sled_drive_count = None;
  }

  pub fn set_storage_class(&mut self, storage_class: String) {
    self.storage_class = Some(storage_class);
  }

  pub fn with_storage_class(mut self, storage_class: String) -> NodeHardwareNode {
    self.storage_class = Some(storage_class);
    self
  }

  pub fn storage_class(&self) -> Option<&String> {
    self.storage_class.as_ref()
  }

  pub fn reset_storage_class(&mut self) {
    self.storage_class = None;
  }

  pub fn set_tier(&mut self, tier: i32) {
    self.tier = Some(tier);
  }

  pub fn with_tier(mut self, tier: i32) -> NodeHardwareNode {
    self.tier = Some(tier);
    self
  }

  pub fn tier(&self) -> Option<&i32> {
    self.tier.as_ref()
  }

  pub fn reset_tier(&mut self) {
    self.tier = None;
  }

  pub fn set_top_level_assembly_serial_number(&mut self, top_level_assembly_serial_number: String) {
    self.top_level_assembly_serial_number = top_level_assembly_serial_number;
  }

  pub fn with_top_level_assembly_serial_number(mut self, top_level_assembly_serial_number: String) -> NodeHardwareNode {
    self.top_level_assembly_serial_number = top_level_assembly_serial_number;
    self
  }

  pub fn top_level_assembly_serial_number(&self) -> &String {
    &self.top_level_assembly_serial_number
  }


}



