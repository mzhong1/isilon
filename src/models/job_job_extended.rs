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
pub struct JobJobExtended {
  /// State to which the job is transitioning; if control_state is identical to state, the job's state is stable.
  #[serde(rename = "control_state")]
  control_state: Option<String>,
  /// The time the job was queued, in seconds since the epoch.
  #[serde(rename = "create_time")]
  create_time: i32,
  /// The current phase of the job.
  #[serde(rename = "current_phase")]
  current_phase: Option<i32>,
  /// A text representation of the job.
  #[serde(rename = "description")]
  description: Option<String>,
  /// The time the job ended, in seconds since the Epoch.
  #[serde(rename = "end_time")]
  end_time: Option<i32>,
  /// The ID of the job.
  #[serde(rename = "id")]
  id: i32,
  /// The current impact of the job.
  #[serde(rename = "impact")]
  impact: String,
  /// The set of devids working on the job.
  #[serde(rename = "participants")]
  participants: Option<Vec<i32>>,
  /// Paths for which the job was queued.
  #[serde(rename = "paths")]
  paths: Option<Vec<String>>,
  /// Current impact policy of the job.
  #[serde(rename = "policy")]
  policy: String,
  /// Current priority of the job; lower numbers preempt higher numbers.
  #[serde(rename = "priority")]
  priority: i32,
  /// A text representation of the job's progress.
  #[serde(rename = "progress")]
  progress: Option<String>,
  /// The number of retries remaining if the job fails.
  #[serde(rename = "retries_remaining")]
  retries_remaining: i32,
  /// The number of seconds the job has executed.
  #[serde(rename = "running_time")]
  running_time: Option<i32>,
  /// The time the job started, in seconds since the Epoch.
  #[serde(rename = "start_time")]
  start_time: Option<i32>,
  /// Current state of the job.
  #[serde(rename = "state")]
  state: String,
  /// The total number of phases of the job type.
  #[serde(rename = "total_phases")]
  total_phases: i32,
  /// The job type.
  #[serde(rename = "type")]
  _type: String,
  /// The ID of a job for which this job is waiting.
  #[serde(rename = "waiting_on")]
  waiting_on: Option<i32>,
  /// The reason the job is waiting.
  #[serde(rename = "waiting_reason")]
  waiting_reason: Option<String>
}

impl JobJobExtended {
  pub fn new(create_time: i32, id: i32, impact: String, policy: String, priority: i32, retries_remaining: i32, state: String, total_phases: i32, _type: String) -> JobJobExtended {
    JobJobExtended {
      control_state: None,
      create_time: create_time,
      current_phase: None,
      description: None,
      end_time: None,
      id: id,
      impact: impact,
      participants: None,
      paths: None,
      policy: policy,
      priority: priority,
      progress: None,
      retries_remaining: retries_remaining,
      running_time: None,
      start_time: None,
      state: state,
      total_phases: total_phases,
      _type: _type,
      waiting_on: None,
      waiting_reason: None
    }
  }

  pub fn set_control_state(&mut self, control_state: String) {
    self.control_state = Some(control_state);
  }

  pub fn with_control_state(mut self, control_state: String) -> JobJobExtended {
    self.control_state = Some(control_state);
    self
  }

  pub fn control_state(&self) -> Option<&String> {
    self.control_state.as_ref()
  }

  pub fn reset_control_state(&mut self) {
    self.control_state = None;
  }

  pub fn set_create_time(&mut self, create_time: i32) {
    self.create_time = create_time;
  }

  pub fn with_create_time(mut self, create_time: i32) -> JobJobExtended {
    self.create_time = create_time;
    self
  }

  pub fn create_time(&self) -> &i32 {
    &self.create_time
  }


  pub fn set_current_phase(&mut self, current_phase: i32) {
    self.current_phase = Some(current_phase);
  }

  pub fn with_current_phase(mut self, current_phase: i32) -> JobJobExtended {
    self.current_phase = Some(current_phase);
    self
  }

  pub fn current_phase(&self) -> Option<&i32> {
    self.current_phase.as_ref()
  }

  pub fn reset_current_phase(&mut self) {
    self.current_phase = None;
  }

  pub fn set_description(&mut self, description: String) {
    self.description = Some(description);
  }

  pub fn with_description(mut self, description: String) -> JobJobExtended {
    self.description = Some(description);
    self
  }

  pub fn description(&self) -> Option<&String> {
    self.description.as_ref()
  }

  pub fn reset_description(&mut self) {
    self.description = None;
  }

  pub fn set_end_time(&mut self, end_time: i32) {
    self.end_time = Some(end_time);
  }

  pub fn with_end_time(mut self, end_time: i32) -> JobJobExtended {
    self.end_time = Some(end_time);
    self
  }

  pub fn end_time(&self) -> Option<&i32> {
    self.end_time.as_ref()
  }

  pub fn reset_end_time(&mut self) {
    self.end_time = None;
  }

  pub fn set_id(&mut self, id: i32) {
    self.id = id;
  }

  pub fn with_id(mut self, id: i32) -> JobJobExtended {
    self.id = id;
    self
  }

  pub fn id(&self) -> &i32 {
    &self.id
  }


  pub fn set_impact(&mut self, impact: String) {
    self.impact = impact;
  }

  pub fn with_impact(mut self, impact: String) -> JobJobExtended {
    self.impact = impact;
    self
  }

  pub fn impact(&self) -> &String {
    &self.impact
  }


  pub fn set_participants(&mut self, participants: Vec<i32>) {
    self.participants = Some(participants);
  }

  pub fn with_participants(mut self, participants: Vec<i32>) -> JobJobExtended {
    self.participants = Some(participants);
    self
  }

  pub fn participants(&self) -> Option<&Vec<i32>> {
    self.participants.as_ref()
  }

  pub fn reset_participants(&mut self) {
    self.participants = None;
  }

  pub fn set_paths(&mut self, paths: Vec<String>) {
    self.paths = Some(paths);
  }

  pub fn with_paths(mut self, paths: Vec<String>) -> JobJobExtended {
    self.paths = Some(paths);
    self
  }

  pub fn paths(&self) -> Option<&Vec<String>> {
    self.paths.as_ref()
  }

  pub fn reset_paths(&mut self) {
    self.paths = None;
  }

  pub fn set_policy(&mut self, policy: String) {
    self.policy = policy;
  }

  pub fn with_policy(mut self, policy: String) -> JobJobExtended {
    self.policy = policy;
    self
  }

  pub fn policy(&self) -> &String {
    &self.policy
  }


  pub fn set_priority(&mut self, priority: i32) {
    self.priority = priority;
  }

  pub fn with_priority(mut self, priority: i32) -> JobJobExtended {
    self.priority = priority;
    self
  }

  pub fn priority(&self) -> &i32 {
    &self.priority
  }


  pub fn set_progress(&mut self, progress: String) {
    self.progress = Some(progress);
  }

  pub fn with_progress(mut self, progress: String) -> JobJobExtended {
    self.progress = Some(progress);
    self
  }

  pub fn progress(&self) -> Option<&String> {
    self.progress.as_ref()
  }

  pub fn reset_progress(&mut self) {
    self.progress = None;
  }

  pub fn set_retries_remaining(&mut self, retries_remaining: i32) {
    self.retries_remaining = retries_remaining;
  }

  pub fn with_retries_remaining(mut self, retries_remaining: i32) -> JobJobExtended {
    self.retries_remaining = retries_remaining;
    self
  }

  pub fn retries_remaining(&self) -> &i32 {
    &self.retries_remaining
  }


  pub fn set_running_time(&mut self, running_time: i32) {
    self.running_time = Some(running_time);
  }

  pub fn with_running_time(mut self, running_time: i32) -> JobJobExtended {
    self.running_time = Some(running_time);
    self
  }

  pub fn running_time(&self) -> Option<&i32> {
    self.running_time.as_ref()
  }

  pub fn reset_running_time(&mut self) {
    self.running_time = None;
  }

  pub fn set_start_time(&mut self, start_time: i32) {
    self.start_time = Some(start_time);
  }

  pub fn with_start_time(mut self, start_time: i32) -> JobJobExtended {
    self.start_time = Some(start_time);
    self
  }

  pub fn start_time(&self) -> Option<&i32> {
    self.start_time.as_ref()
  }

  pub fn reset_start_time(&mut self) {
    self.start_time = None;
  }

  pub fn set_state(&mut self, state: String) {
    self.state = state;
  }

  pub fn with_state(mut self, state: String) -> JobJobExtended {
    self.state = state;
    self
  }

  pub fn state(&self) -> &String {
    &self.state
  }


  pub fn set_total_phases(&mut self, total_phases: i32) {
    self.total_phases = total_phases;
  }

  pub fn with_total_phases(mut self, total_phases: i32) -> JobJobExtended {
    self.total_phases = total_phases;
    self
  }

  pub fn total_phases(&self) -> &i32 {
    &self.total_phases
  }


  pub fn set__type(&mut self, _type: String) {
    self._type = _type;
  }

  pub fn with__type(mut self, _type: String) -> JobJobExtended {
    self._type = _type;
    self
  }

  pub fn _type(&self) -> &String {
    &self._type
  }


  pub fn set_waiting_on(&mut self, waiting_on: i32) {
    self.waiting_on = Some(waiting_on);
  }

  pub fn with_waiting_on(mut self, waiting_on: i32) -> JobJobExtended {
    self.waiting_on = Some(waiting_on);
    self
  }

  pub fn waiting_on(&self) -> Option<&i32> {
    self.waiting_on.as_ref()
  }

  pub fn reset_waiting_on(&mut self) {
    self.waiting_on = None;
  }

  pub fn set_waiting_reason(&mut self, waiting_reason: String) {
    self.waiting_reason = Some(waiting_reason);
  }

  pub fn with_waiting_reason(mut self, waiting_reason: String) -> JobJobExtended {
    self.waiting_reason = Some(waiting_reason);
    self
  }

  pub fn waiting_reason(&self) -> Option<&String> {
    self.waiting_reason.as_ref()
  }

  pub fn reset_waiting_reason(&mut self) {
    self.waiting_reason = None;
  }

}



