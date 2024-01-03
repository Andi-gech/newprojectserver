const mongoose = require('mongoose');

const mainDataStore = new mongoose.Schema({
  Location: { type: String, required: true },
  Zetacode: { type: Number, required: true, unique: true },
  Room: { type: String, required: true },
  HelpDeskReference: { type: String, required: true },
  IPS: { type: Boolean, required: true },
  Fault: { type: String},
  Date: { type: Date, required: true },
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