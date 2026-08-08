#pragma once

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

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

// Comparison applied on "Next Scan" against the previous/snapshot values.
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

// One copied memory region, used by the unknown-initial-value scan.
struct SnapshotRegion
{
	uintptr_t baseAddress;
	std::vector<unsigned char> data; // full copy of the region at scan time
};

class MemoryScanner
{
public:
	MemoryScanner();
	~MemoryScanner();

	// All scans run on a worker thread so the render thread (and the game)
	// never blocks. Each returns false if a scan is already running.
	// valueBytes must point to ScanValueTypeSize(type) bytes in the target's
	// native little-endian layout.
	bool StartFirstScan(ScanValueType type, const unsigned char* valueBytes);
	bool StartFirstScanUnknown(ScanValueType type);
	bool StartNextScan(ScanCompareType compare, const unsigned char* valueBytes);

	void CancelScan();
	bool IsScanInProgress() const { return m_scanInProgress; }
	float GetScanProgress() const { return m_scanProgress; }      // 0.0 - 1.0
	size_t GetLiveMatchCount() const { return m_liveMatchCount; } // matches found so far
	bool WasSnapshotTooLarge() const { return m_snapshotTooLarge; }

	// Writes size bytes to an address inside this process (internal access,
	// so no OpenProcess/WriteProcessMemory is needed).
	bool WriteValue(uintptr_t address, const unsigned char* valueBytes, size_t size);

	// Reads size bytes from an address. Returns false if not readable.
	bool ReadValue(uintptr_t address, unsigned char* outValue, size_t size);

	// Cancels any running scan and clears all results/snapshot data.
	void Reset();

	ScanValueType GetValueType() const { return m_valueType; }
	const std::vector<ScanMatch>& GetMatches() const { return m_matches; }
	bool HasScanResults() const { return m_hasResults; }

	// True between "Unknown Value" first scan and the first Next Scan.
	// In this mode GetMatches() is empty; candidates live in the snapshot.
	bool IsUnknownValueSnapshot() const { return m_unknownValueMode; }

	size_t GetMatchCount() const
	{
		return m_unknownValueMode ? m_unknownCandidateCount : m_matches.size();
	}

	// Addresses re-written every frame while frozen ("freeze" like Cheat Engine).
	std::vector<FrozenValue> frozenValues;
	void ApplyFrozenValues();

private:
	enum class ScanKind { FirstExact, FirstUnknown, Next };

	void ScanThreadMain();
	void DoFirstScanExact();
	void DoFirstScanUnknown();
	void DoNextScan();
	void JoinScanThread();

	std::vector<ScanMatch> m_matches;
	std::vector<SnapshotRegion> m_snapshot; // unknown-initial-value mode
	ScanValueType m_valueType = ScanValueType::Int32;
	bool m_hasResults = false;
	bool m_unknownValueMode = false;
	size_t m_unknownCandidateCount = 0;

	// Pending scan parameters (written by the UI thread before the worker starts).
	ScanKind m_pendingKind = ScanKind::FirstExact;
	ScanCompareType m_pendingCompare = ScanCompareType::Exact;
	unsigned char m_pendingValue[8] = {};

	std::thread m_scanThread;
	std::atomic<bool> m_scanInProgress;
	std::atomic<bool> m_cancelRequested;
	std::atomic<float> m_scanProgress;
	std::atomic<size_t> m_liveMatchCount;
	std::atomic<bool> m_snapshotTooLarge;
};

// Helpers shared with the UI layer.
size_t ScanValueTypeSize(ScanValueType type);
bool ParseValueText(const char* text, ScanValueType type, unsigned char* outBytes);
std::string FormatValue(const unsigned char* bytes, ScanValueType type);

// ImGui panel, called from RenderImGuiInterface().
void RenderMemoryScannerInterface();

extern MemoryScanner g_memoryScanner;
