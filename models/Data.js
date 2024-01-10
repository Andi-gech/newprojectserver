const mongoose = require('mongoose');

const mainDataStore = new mongoose.Schema({
  Location: { type: String},
  Zetacode: { type: Number },
  Room: { type: String},
  HelpDeskReference: { type: String},
  IPS: { type: Boolean },
  Fault: { type: String},
  Date: { type: Date },
  HotTemperature: { type: Number},
  HotFlow: { type: Number},
  HotReturn: { type: Number},
  ColdTemperature: { type: Number},
  ColdFlow: { type: Number},
  ColdReturn: { type: Number},
  HotFlushTemperature: { type: Number},
  TapNotSet: {type: Boolean},
  ColdFlushTemperature: { type: Number},
  TMVFail: {type: Boolean},
  PreflushSampleTaken: {type: Boolean},
  PostflushSampleTaken: {type: Boolean},
  ThermalFlush: {type: String},
 
  additionalData: { type: mongoose.Schema.Types.Mixed },
});

const MainData = mongoose.model('MainData', mainDataStore);

module.exports = MainData;