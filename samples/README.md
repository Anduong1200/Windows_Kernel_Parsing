# Sample Data for Logic Flow Analysis

This directory contains sample Windows kernel driver files for testing and demonstration purposes.

## 🚨 Important Notice

**These are demonstration files only and should not be used in production environments.**

The sample drivers are:
- Minimal synthetic drivers created for testing
- Not real Windows kernel drivers
- Safe to analyze but contain no actual functionality

## 📁 Sample Files

### Available Samples
- `sample_driver_v1.sys` - Baseline reference driver
- `sample_driver_v2.sys` - Modified version with logic changes

### How to Use

1. Place these files in a test directory
2. Use `sample_driver_v1.sys` as "Reference Driver A"
3. Use `sample_driver_v2.sys` as "Target Driver B"
4. Run analysis to see logic flow comparison

## 🔍 Analysis Expectations

When analyzing these samples, you should see:
- Basic function structure comparison
- Logic flow differences (if any)
- Error handling pattern analysis
- Resource management verification

## ⚠️ Security Note

While these samples are safe, always ensure you have proper authorization before analyzing any real Windows kernel drivers or system files.

## 📝 Creating Your Own Samples

For real analysis:
1. Obtain legitimate driver files from trusted sources
2. Ensure you have proper legal authorization
3. Use different versions of the same driver for comparison
4. Include crash dump information if available

## 🤝 Contributing Samples

If you have safe, synthetic driver samples that would help demonstrate specific analysis scenarios, please contribute them to this directory.
