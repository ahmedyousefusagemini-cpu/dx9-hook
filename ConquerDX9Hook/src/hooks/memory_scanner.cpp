#include "common.h"
#include "memory_scanner.h"
#include "imgui.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

MemoryScanner g_memoryScanner;

// Upper bound of 32-bit user-mode address space.
static const uintptr_t USER_SPACE_END = 0x7FFE0000;

// Safety cap so a broad scan cannot exhaust memory.
static const size_t MAX_MATCHES = 2000000;

// Regions are processed in 1 MB chunks to bound temporary allocations.
static const size_t SCAN_CHUNK_SIZE = 1024 * 1024;

// Unknown-initial-value scans copy whole regions; cap the total copy size
// (the 32-bit process only has ~2 GB of address space, shared with the game).
static const size_t MAX_SNAPSHOT_BYTES = 512ull * 1024 * 1024;

size_t ScanValueTypeSize(ScanValueType type)
{
	switch (type)
	{
	case ScanValueType::Int32:
	case ScanValueType::UInt32:
	case ScanValueType::Float:
		return 4;
	case ScanValueType::Double:
	case ScanValueType::Int64:
		return 8;
	case ScanValueType::Byte:
		return 1;
	case ScanValueType::Int16:
		return 2;
	}
	return 4;
}

// This DLL runs inside the game process, so memory is accessed directly.
// The SEH guard survives regions being freed mid-scan by other threads.
static bool SafeReadMemory(uintptr_t address, void* buffer, size_t size)
{
	__try
	{
		memcpy(buffer, reinterpret_cast<const void*>(address), size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}
	return true;
}

template <typename T>
static bool CompareValues(ScanCompareType compare, const unsigned char* current,
	const unsigned char* previous, const unsigned char* target)
{
	T currentValue = *reinterpret_cast<const T*>(current);
	T previousValue = *reinterpret_cast<const T*>(previous);
	T targetValue = *reinterpret_cast<const T*>(target);

	switch (compare)
	{
	case ScanCompareType::Exact:		return currentValue == targetValue;
	case ScanCompareType::Changed:		return currentValue != previousValue;
	case ScanCompareType::Unchanged:	return currentValue == previousValue;
	case ScanCompareType::Increased:	return currentValue > previousValue;
	case ScanCompareType::Decreased:	return currentValue < previousValue;
	}
	return false;
}

static bool CompareDispatch(ScanValueType type, ScanCompareType compare,
	const unsigned char* current, const unsigned char* previous, const unsigned char* target)
{
	switch (type)
	{
	case ScanValueType::Int32:		return CompareValues<int>(compare, current, previous, target);
	case ScanValueType::UInt32:		return CompareValues<unsigned int>(compare, current, previous, target);
	case ScanValueType::Float:		return CompareValues<float>(compare, current, previous, target);
	case ScanValueType::Double:		return CompareValues<double>(compare, current, previous, target);
	case ScanValueType::Byte:		return CompareValues<unsigned char>(compare, current, previous, target);
	case ScanValueType::Int16:		return CompareValues<short>(compare, current, previous, target);
	case ScanValueType::Int64:		return CompareValues<long long>(compare, current, previous, target);
	}
	return false;
}

static bool IsScannableProtection(DWORD protect)
{
	if (protect & (PAGE_GUARD | PAGE_NOACCESS))
		return false;
	return (protect & (PAGE_READWRITE | PAGE_WRITECOPY |
		PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

MemoryScanner::MemoryScanner()
	: m_scanInProgress(false), m_cancelRequested(false),
	m_scanProgress(0.0f), m_liveMatchCount(0), m_snapshotTooLarge(false)
{
}

MemoryScanner::~MemoryScanner()
{
	CancelScan();
	JoinScanThread();
}

void MemoryScanner::JoinScanThread()
{
	if (m_scanThread.joinable())
		m_scanThread.join();
}

void MemoryScanner::CancelScan()
{
	m_cancelRequested = true;
}

bool MemoryScanner::StartFirstScan(ScanValueType type, const unsigned char* valueBytes)
{
	if (m_scanInProgress)
		return false;
	JoinScanThread();

	m_pendingKind = ScanKind::FirstExact;
	m_valueType = type;
	memset(m_pendingValue, 0, sizeof(m_pendingValue));
	memcpy(m_pendingValue, valueBytes, ScanValueTypeSize(type));

	m_cancelRequested = false;
	m_snapshotTooLarge = false;
	m_scanProgress = 0.0f;
	m_liveMatchCount = 0;
	m_scanInProgress = true;
	m_scanThread = std::thread(&MemoryScanner::ScanThreadMain, this);
	return true;
}

bool MemoryScanner::StartFirstScanUnknown(ScanValueType type)
{
	if (m_scanInProgress)
		return false;
	JoinScanThread();

	m_pendingKind = ScanKind::FirstUnknown;
	m_valueType = type;
	memset(m_pendingValue, 0, sizeof(m_pendingValue));

	m_cancelRequested = false;
	m_snapshotTooLarge = false;
	m_scanProgress = 0.0f;
	m_liveMatchCount = 0;
	m_scanInProgress = true;
	m_scanThread = std::thread(&MemoryScanner::ScanThreadMain, this);
	return true;
}

bool MemoryScanner::StartNextScan(ScanCompareType compare, const unsigned char* valueBytes)
{
	if (m_scanInProgress)
		return false;
	if (!m_hasResults && !m_unknownValueMode)
		return false;
	JoinScanThread();

	m_pendingKind = ScanKind::Next;
	m_pendingCompare = compare;
	memset(m_pendingValue, 0, sizeof(m_pendingValue));
	memcpy(m_pendingValue, valueBytes, ScanValueTypeSize(m_valueType));

	m_cancelRequested = false;
	m_snapshotTooLarge = false;
	m_scanProgress = 0.0f;
	m_liveMatchCount = 0;
	m_scanInProgress = true;
	m_scanThread = std::thread(&MemoryScanner::ScanThreadMain, this);
	return true;
}

void MemoryScanner::ScanThreadMain()
{
	switch (m_pendingKind)
	{
	case ScanKind::FirstExact:		DoFirstScanExact(); break;
	case ScanKind::FirstUnknown:	DoFirstScanUnknown(); break;
	case ScanKind::Next:			DoNextScan(); break;
	}
	m_scanProgress = 1.0f;
	m_scanInProgress = false;
}

void MemoryScanner::DoFirstScanExact()
{
	const size_t valueSize = ScanValueTypeSize(m_valueType);
	std::vector<ScanMatch> results;
	std::vector<unsigned char> buffer;
	buffer.reserve(SCAN_CHUNK_SIZE);

	uintptr_t address = 0x10000; // skip the null-page region
	MEMORY_BASIC_INFORMATION regionInfo;

	while (address < USER_SPACE_END)
	{
		if (m_cancelRequested)
			return; // keep previous results untouched

		m_scanProgress = static_cast<float>(static_cast<double>(address) / USER_SPACE_END);

		if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &regionInfo, sizeof(regionInfo)))
			break;

		uintptr_t regionBase = reinterpret_cast<uintptr_t>(regionInfo.BaseAddress);
		uintptr_t regionEnd = regionBase + regionInfo.RegionSize;
		if (regionEnd > USER_SPACE_END)
			regionEnd = USER_SPACE_END;

		bool scannable = regionInfo.State == MEM_COMMIT && IsScannableProtection(regionInfo.Protect);

		if (scannable)
		{
			// Overlap chunks by (valueSize - 1) so values crossing a chunk
			// boundary are still found.
			for (uintptr_t chunk = regionBase; chunk < regionEnd; chunk += SCAN_CHUNK_SIZE - (valueSize - 1))
			{
				if (m_cancelRequested)
					return;

				size_t bytesToRead = (regionEnd - chunk < SCAN_CHUNK_SIZE)
					? static_cast<size_t>(regionEnd - chunk)
					: SCAN_CHUNK_SIZE;

				buffer.resize(bytesToRead);
				if (!SafeReadMemory(chunk, buffer.data(), bytesToRead))
					continue;

				for (size_t i = 0; i + valueSize <= bytesToRead; i++)
				{
					// Only check naturally aligned addresses (power-of-two sizes),
					// matching Cheat Engine's default "fast scan" alignment.
					if (valueSize > 1 && ((chunk + i) & (valueSize - 1)) != 0)
						continue;

					if (memcmp(buffer.data() + i, m_pendingValue, valueSize) == 0)
					{
						ScanMatch match;
						match.address = chunk + i;
						memset(match.previousValue, 0, sizeof(match.previousValue));
						memcpy(match.previousValue, buffer.data() + i, valueSize);
						results.push_back(match);
						m_liveMatchCount = results.size();

						if (results.size() >= MAX_MATCHES)
							goto scanComplete;
					}
				}
			}
		}

		if (regionEnd <= regionBase) // overflow safety
			break;
		address = regionEnd;
	}

scanComplete:
	m_snapshot.clear();
	m_snapshot.shrink_to_fit();
	m_matches.swap(results);
	m_unknownValueMode = false;
	m_hasResults = true;
	m_liveMatchCount = m_matches.size();
}

void MemoryScanner::DoFirstScanUnknown()
{
	const size_t valueSize = ScanValueTypeSize(m_valueType);
	std::vector<SnapshotRegion> snapshot;
	size_t totalBytes = 0;
	size_t candidateCount = 0;

	uintptr_t address = 0x10000;
	MEMORY_BASIC_INFORMATION regionInfo;

	while (address < USER_SPACE_END)
	{
		if (m_cancelRequested)
			return;

		m_scanProgress = static_cast<float>(static_cast<double>(address) / USER_SPACE_END);

		if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &regionInfo, sizeof(regionInfo)))
			break;

		uintptr_t regionBase = reinterpret_cast<uintptr_t>(regionInfo.BaseAddress);
		uintptr_t regionEnd = regionBase + regionInfo.RegionSize;
		if (regionEnd > USER_SPACE_END)
			regionEnd = USER_SPACE_END;

		bool scannable = regionInfo.State == MEM_COMMIT && IsScannableProtection(regionInfo.Protect);

		if (scannable && regionEnd > regionBase)
		{
			size_t regionSize = static_cast<size_t>(regionEnd - regionBase);

			if (totalBytes + regionSize > MAX_SNAPSHOT_BYTES)
			{
				m_snapshotTooLarge = true;
				return; // keep previous results untouched
			}

			SnapshotRegion region;
			region.baseAddress = regionBase;
			region.data.resize(regionSize);

			// Copy the region in chunks. Chunks that vanish mid-copy are left
			// as zeros so offsets inside the snapshot stay consistent.
			for (size_t offset = 0; offset < regionSize; offset += SCAN_CHUNK_SIZE)
			{
				if (m_cancelRequested)
					return;

				size_t bytesToRead = (regionSize - offset < SCAN_CHUNK_SIZE)
					? (regionSize - offset)
					: SCAN_CHUNK_SIZE;
				SafeReadMemory(regionBase + offset, region.data.data() + offset, bytesToRead);
			}

			totalBytes += regionSize;
			candidateCount += regionSize / valueSize;
			m_liveMatchCount = candidateCount;
			snapshot.push_back(std::move(region));
		}

		if (regionEnd <= regionBase)
			break;
		address = regionEnd;
	}

	m_matches.clear();
	m_snapshot.swap(snapshot);
	m_unknownValueMode = true;
	m_unknownCandidateCount = candidateCount;
	m_hasResults = false;
	m_liveMatchCount = candidateCount;
}

void MemoryScanner::DoNextScan()
{
	const size_t valueSize = ScanValueTypeSize(m_valueType);
	std::vector<ScanMatch> filtered;

	if (m_unknownValueMode)
	{
		// Filter the snapshot against live memory, producing a compact
		// match list; the snapshot is then discarded to free memory.
		size_t totalBytes = 0;
		for (size_t r = 0; r < m_snapshot.size(); r++)
			totalBytes += m_snapshot[r].data.size();

		size_t processedBytes = 0;
		std::vector<unsigned char> liveBuffer;
		liveBuffer.reserve(SCAN_CHUNK_SIZE);

		for (size_t r = 0; r < m_snapshot.size(); r++)
		{
			const SnapshotRegion& region = m_snapshot[r];

			for (size_t offset = 0; offset < region.data.size(); offset += SCAN_CHUNK_SIZE)
			{
				if (m_cancelRequested)
					return; // keep the snapshot so the user can retry

				size_t bytesToRead = (region.data.size() - offset < SCAN_CHUNK_SIZE)
					? (region.data.size() - offset)
					: SCAN_CHUNK_SIZE;

				liveBuffer.resize(bytesToRead);
				if (!SafeReadMemory(region.baseAddress + offset, liveBuffer.data(), bytesToRead))
				{
					processedBytes += bytesToRead;
					continue;
				}

				for (size_t i = 0; i + valueSize <= bytesToRead; i++)
				{
					if (valueSize > 1 && ((region.baseAddress + offset + i) & (valueSize - 1)) != 0)
						continue;

					if (CompareDispatch(m_valueType, m_pendingCompare,
						liveBuffer.data() + i, region.data.data() + offset + i, m_pendingValue))
					{
						ScanMatch match;
						match.address = region.baseAddress + offset + i;
						memset(match.previousValue, 0, sizeof(match.previousValue));
						memcpy(match.previousValue, liveBuffer.data() + i, valueSize);
						filtered.push_back(match);

						if (filtered.size() >= MAX_MATCHES)
							goto nextScanComplete;
					}
				}

				processedBytes += bytesToRead;
				if (totalBytes > 0)
					m_scanProgress = static_cast<float>(static_cast<double>(processedBytes) / totalBytes);
				m_liveMatchCount = filtered.size();
			}
		}

	nextScanComplete:
		m_snapshot.clear();
		m_snapshot.shrink_to_fit();
		m_matches.swap(filtered);
		m_unknownValueMode = false;
		m_hasResults = true;
		m_liveMatchCount = m_matches.size();
	}
	else
	{
		// Refine the existing compact match list.
		const size_t matchCount = m_matches.size();
		filtered.reserve(matchCount);

		for (size_t i = 0; i < matchCount; i++)
		{
			if (m_cancelRequested)
				return;

			if ((i & 0x3FFF) == 0)
			{
				m_scanProgress = matchCount > 0 ? static_cast<float>(static_cast<double>(i) / matchCount) : 1.0f;
				m_liveMatchCount = filtered.size();
			}

			unsigned char currentValue[8] = {};
			if (!SafeReadMemory(m_matches[i].address, currentValue, valueSize))
				continue;

			if (CompareDispatch(m_valueType, m_pendingCompare,
				currentValue, m_matches[i].previousValue, m_pendingValue))
			{
				ScanMatch match;
				match.address = m_matches[i].address;
				memcpy(match.previousValue, currentValue, sizeof(match.previousValue));
				filtered.push_back(match);
			}
		}

		m_matches.swap(filtered);
		m_liveMatchCount = m_matches.size();
	}
}

bool MemoryScanner::ReadValue(uintptr_t address, unsigned char* outValue, size_t size)
{
	return SafeReadMemory(address, outValue, size);
}

bool MemoryScanner::WriteValue(uintptr_t address, const unsigned char* valueBytes, size_t size)
{
	DWORD oldProtect = 0;
	if (!VirtualProtect(reinterpret_cast<LPVOID>(address), size, PAGE_READWRITE, &oldProtect))
		return false;

	bool success = true;
	__try
	{
		memcpy(reinterpret_cast<void*>(address), valueBytes, size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		success = false;
	}

	DWORD ignored = 0;
	VirtualProtect(reinterpret_cast<LPVOID>(address), size, oldProtect, &ignored);
	return success;
}

void MemoryScanner::Reset()
{
	CancelScan();
	JoinScanThread();

	m_matches.clear();
	m_snapshot.clear();
	m_snapshot.shrink_to_fit();
	m_hasResults = false;
	m_unknownValueMode = false;
	m_unknownCandidateCount = 0;
	m_cancelRequested = false;
	m_snapshotTooLarge = false;
	m_scanProgress = 0.0f;
	m_liveMatchCount = 0;
}

void MemoryScanner::ApplyFrozenValues()
{
	for (size_t i = 0; i < frozenValues.size(); i++)
	{
		WriteValue(frozenValues[i].address, frozenValues[i].value, frozenValues[i].size);
	}
}

bool ParseValueText(const char* text, ScanValueType type, unsigned char* outBytes)
{
	memset(outBytes, 0, 8);
	char* end = nullptr;

	switch (type)
	{
	case ScanValueType::Int32:
	{
		int value = static_cast<int>(_strtoi64(text, &end, 0));
		if (end == text) return false;
		memcpy(outBytes, &value, sizeof(value));
		return true;
	}
	case ScanValueType::UInt32:
	{
		unsigned int value = static_cast<unsigned int>(_strtoui64(text, &end, 0));
		if (end == text) return false;
		memcpy(outBytes, &value, sizeof(value));
		return true;
	}
	case ScanValueType::Float:
	{
		float value = strtof(text, &end);
		if (end == text) return false;
		memcpy(outBytes, &value, sizeof(value));
		return true;
	}
	case ScanValueType::Double:
	{
		double value = strtod(text, &end);
		if (end == text) return false;
		memcpy(outBytes, &value, sizeof(value));
		return true;
	}
	case ScanValueType::Byte:
	{
		unsigned long value = strtoul(text, &end, 0);
		if (end == text || value > 0xFF) return false;
		*outBytes = static_cast<unsigned char>(value);
		return true;
	}
	case ScanValueType::Int16:
	{
		short value = static_cast<short>(strtol(text, &end, 0));
		if (end == text) return false;
		memcpy(outBytes, &value, sizeof(value));
		return true;
	}
	case ScanValueType::Int64:
	{
		long long value = _strtoi64(text, &end, 0);
		if (end == text) return false;
		memcpy(outBytes, &value, sizeof(value));
		return true;
	}
	}
	return false;
}

std::string FormatValue(const unsigned char* bytes, ScanValueType type)
{
	char text[64];
	switch (type)
	{
	case ScanValueType::Int32:	sprintf_s(text, "%d", *reinterpret_cast<const int*>(bytes)); break;
	case ScanValueType::UInt32:	sprintf_s(text, "%u", *reinterpret_cast<const unsigned int*>(bytes)); break;
	case ScanValueType::Float:	sprintf_s(text, "%.4f", *reinterpret_cast<const float*>(bytes)); break;
	case ScanValueType::Double:	sprintf_s(text, "%.4f", *reinterpret_cast<const double*>(bytes)); break;
	case ScanValueType::Byte:	sprintf_s(text, "%u", static_cast<unsigned int>(*bytes)); break;
	case ScanValueType::Int16:	sprintf_s(text, "%d", static_cast<int>(*reinterpret_cast<const short*>(bytes))); break;
	case ScanValueType::Int64:	sprintf_s(text, "%lld", *reinterpret_cast<const long long*>(bytes)); break;
	default:					sprintf_s(text, "?"); break;
	}
	return text;
}

void RenderMemoryScannerInterface()
{
	static int valueTypeIndex = 0;
	static int compareTypeIndex = 0;
	static char valueInput[64] = "0";
	static char writeInput[64] = "0";
	static int selectedMatch = -1;
	static bool wasScanning = false;
	static char statusText[192] = "Pick a type, enter a value, press First Scan (or Unknown Value).";

	static const char* valueTypes[] = { "Int32", "UInt32", "Float", "Double", "Byte", "Int16", "Int64" };
	static const char* compareTypes[] = { "Exact Value", "Changed Value", "Unchanged Value", "Increased Value", "Decreased Value" };

	ScanValueType valueType = static_cast<ScanValueType>(valueTypeIndex);
	size_t valueSize = ScanValueTypeSize(valueType);
	bool scanInProgress = g_memoryScanner.IsScanInProgress();

	// Detect scan completion and refresh the status line.
	if (wasScanning && !scanInProgress)
	{
		if (g_memoryScanner.WasSnapshotTooLarge())
		{
			sprintf_s(statusText, "Snapshot exceeded the 512 MB limit. Scan was aborted.");
		}
		else if (g_memoryScanner.IsUnknownValueSnapshot())
		{
			sprintf_s(statusText, "Snapshot complete: %u candidates. Change the value in-game, pick a comparison, press Next Scan.",
				static_cast<unsigned int>(g_memoryScanner.GetMatchCount()));
		}
		else if (g_memoryScanner.HasScanResults())
		{
			sprintf_s(statusText, "Scan complete: %u matches.",
				static_cast<unsigned int>(g_memoryScanner.GetMatchCount()));
		}
		else
		{
			sprintf_s(statusText, "Scan cancelled.");
		}
	}
	wasScanning = scanInProgress;

	ImGui::PushItemWidth(110);
	int previousTypeIndex = valueTypeIndex;
	ImGui::Combo("Type", &valueTypeIndex, valueTypes, IM_ARRAYSIZE(valueTypes));
	ImGui::SameLine();
	ImGui::Combo("Compare", &compareTypeIndex, compareTypes, IM_ARRAYSIZE(compareTypes));
	ImGui::PopItemWidth();

	// Changing the value type invalidates previous results (sizes differ).
	if (valueTypeIndex != previousTypeIndex && !scanInProgress)
	{
		g_memoryScanner.Reset();
		selectedMatch = -1;
		valueType = static_cast<ScanValueType>(valueTypeIndex);
		valueSize = ScanValueTypeSize(valueType);
	}

	ImGui::PushItemWidth(180);
	ImGui::InputText("Value", valueInput, sizeof(valueInput));
	ImGui::PopItemWidth();

	if (!scanInProgress)
	{
		if (ImGui::Button("First Scan"))
		{
			unsigned char valueBytes[8];
			if (!ParseValueText(valueInput, valueType, valueBytes))
			{
				sprintf_s(statusText, "Invalid value for type %s.", valueTypes[valueTypeIndex]);
			}
			else
			{
				selectedMatch = -1;
				g_memoryScanner.StartFirstScan(valueType, valueBytes);
				sprintf_s(statusText, "First scan running...");
			}
		}
		ImGui::SameLine();

		if (ImGui::Button("Unknown Value"))
		{
			selectedMatch = -1;
			g_memoryScanner.StartFirstScanUnknown(valueType);
			sprintf_s(statusText, "Taking memory snapshot...");
		}
		ImGui::SameLine();

		if (ImGui::Button("Next Scan"))
		{
			if (!g_memoryScanner.HasScanResults() && !g_memoryScanner.IsUnknownValueSnapshot())
			{
				sprintf_s(statusText, "Run a First Scan (or Unknown Value) first.");
			}
			else
			{
				unsigned char valueBytes[8] = {};
				if (static_cast<ScanCompareType>(compareTypeIndex) == ScanCompareType::Exact &&
					!ParseValueText(valueInput, valueType, valueBytes))
				{
					sprintf_s(statusText, "Invalid value for type %s.", valueTypes[valueTypeIndex]);
				}
				else
				{
					selectedMatch = -1;
					g_memoryScanner.StartNextScan(static_cast<ScanCompareType>(compareTypeIndex), valueBytes);
					sprintf_s(statusText, "Next scan running...");
				}
			}
		}
		ImGui::SameLine();

		if (ImGui::Button("New Scan"))
		{
			g_memoryScanner.Reset();
			selectedMatch = -1;
			sprintf_s(statusText, "Scan reset. Enter a value and press First Scan.");
		}
	}
	else
	{
		if (ImGui::Button("Cancel Scan"))
			g_memoryScanner.CancelScan();

		char overlay[96];
		float progress = g_memoryScanner.GetScanProgress();
		sprintf_s(overlay, "%.0f%% (%u found)", progress * 100.0f,
			static_cast<unsigned int>(g_memoryScanner.GetLiveMatchCount()));
		ImGui::ProgressBar(progress, ImVec2(-1, 0), overlay);
	}

	ImGui::TextWrapped("%s", statusText);

	// ---- Results list -----------------------------------------------------
	if (!scanInProgress && !g_memoryScanner.IsUnknownValueSnapshot())
	{
		const std::vector<ScanMatch>& matches = g_memoryScanner.GetMatches();
		const size_t displayLimit = 2000; // keep the list UI responsive
		int displayCount = static_cast<int>(matches.size() < displayLimit ? matches.size() : displayLimit);

		if (matches.size() > displayLimit)
			ImGui::TextWrapped("Showing first %u results. Refine with Next Scan.", static_cast<unsigned int>(displayLimit));

		if (displayCount > 0)
		{
			ImGui::BeginChild("ScanResults", ImVec2(0, 150), true);

			ImGuiListClipper clipper;
			clipper.Begin(displayCount);
			while (clipper.Step())
			{
				for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
				{
					ImGui::PushID(i);

					unsigned char currentValue[8] = {};
					g_memoryScanner.ReadValue(matches[i].address, currentValue, valueSize);

					char label[128];
					sprintf_s(label, "0x%08X = %s", static_cast<unsigned int>(matches[i].address),
						FormatValue(currentValue, valueType).c_str());

					if (ImGui::Selectable(label, selectedMatch == i))
					{
						selectedMatch = i;
						std::string current = FormatValue(currentValue, valueType);
						sprintf_s(writeInput, "%s", current.c_str());
					}

					ImGui::PopID();
				}
			}
			clipper.End();

			ImGui::EndChild();
		}

		// ---- Write / freeze controls ----------------------------------------
		bool hasSelection = selectedMatch >= 0 && selectedMatch < static_cast<int>(matches.size());
		if (hasSelection)
			ImGui::Text("Selected: 0x%08X", static_cast<unsigned int>(matches[selectedMatch].address));
		else
			ImGui::Text("Selected: (click a result above)");

		ImGui::PushItemWidth(180);
		ImGui::InputText("New Value", writeInput, sizeof(writeInput));
		ImGui::PopItemWidth();

		if (ImGui::Button("Write") && hasSelection)
		{
			unsigned char valueBytes[8];
			if (ParseValueText(writeInput, valueType, valueBytes) &&
				g_memoryScanner.WriteValue(matches[selectedMatch].address, valueBytes, valueSize))
			{
				sprintf_s(statusText, "Wrote %s to 0x%08X.", FormatValue(valueBytes, valueType).c_str(),
					static_cast<unsigned int>(matches[selectedMatch].address));
			}
			else
			{
				sprintf_s(statusText, "Write failed (bad value or unreadable address).");
			}
		}
		ImGui::SameLine();

		if (ImGui::Button("Freeze") && hasSelection)
		{
			unsigned char valueBytes[8];
			if (ParseValueText(writeInput, valueType, valueBytes))
			{
				FrozenValue frozen;
				frozen.address = matches[selectedMatch].address;
				frozen.size = valueSize;
				memset(frozen.value, 0, sizeof(frozen.value));
				memcpy(frozen.value, valueBytes, valueSize);
				g_memoryScanner.frozenValues.push_back(frozen);
				sprintf_s(statusText, "Froze 0x%08X (%u frozen total).",
					static_cast<unsigned int>(frozen.address),
					static_cast<unsigned int>(g_memoryScanner.frozenValues.size()));
			}
		}
		ImGui::SameLine();

		if (ImGui::Button("Unfreeze All"))
		{
			g_memoryScanner.frozenValues.clear();
			sprintf_s(statusText, "Cleared all frozen values.");
		}
	}
}
