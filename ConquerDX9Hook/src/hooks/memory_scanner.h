#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>

// Value types supported by the scanner (Cheat Engine style basics).
// The numeric order is mirrored by the type combo box in the ImGui panel.
enum class ScanValueType
{
	Int32 = 0,
	UInt32,
	Float,
	Double,
	Byte,
	Int16,
	Int64,
};

// Comparison applied on "Next Scan" against the previous match values.
enum class ScanCompareType
{
	Exact = 0,
	Changed,
	Unchanged,
	Increased,
	Decreased,
};

struct ScanMatch
{
	uintptr_t address;
	unsigned char previousValue[8]; // value captured when this match was recorded
};

struct FrozenValue
{
	uintptr_t address;
	unsigned char value[8];
	size_t size;
};

class MemoryScanner
{
public:
	// Starts a fresh scan over all readable/writable regions of this process.
	// valueBytes must point to ScanValueTypeSize(type) bytes in the target's
	// native little-endian layout. Returns the number of matches found.
	size_t FirstScan(ScanValueType type, const unsigned char* valueBytes);

	// Filters the previous matches using the given comparison.
	// valueBytes is only used for ScanCompareType::Exact.
	// Returns the number of remaining matches.
	size_t NextScan(ScanCompareType compare, const unsigned char* valueBytes);

	// Writes size bytes to an address inside this process (internal access,
	// so no OpenProcess/WriteProcessMemory is needed).
	bool WriteValue(uintptr_t address, const unsigned char* valueBytes, size_t size);

	// Reads size bytes from an address. Returns false if not readable.
	bool ReadValue(uintptr_t address, unsigned char* outValue, size_t size);

	void Reset();

	ScanValueType GetValueType() const { return m_valueType; }
	const std::vector<ScanMatch>& GetMatches() const { return m_matches; }
	bool HasScanResults() const { return m_hasResults; }

	// Addresses re-written every frame while frozen ("freeze" like Cheat Engine).
	std::vector<FrozenValue> frozenValues;
	void ApplyFrozenValues();

private:
	std::vector<ScanMatch> m_matches;
	ScanValueType m_valueType = ScanValueType::Int32;
	bool m_hasResults = false;
};

// Helpers shared with the UI layer.
size_t ScanValueTypeSize(ScanValueType type);
bool ParseValueText(const char* text, ScanValueType type, unsigned char* outBytes);
std::string FormatValue(const unsigned char* bytes, ScanValueType type);

// ImGui panel, called from RenderImGuiInterface().
void RenderMemoryScannerInterface();

extern MemoryScanner g_memoryScanner;
