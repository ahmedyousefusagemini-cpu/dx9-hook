#include "common.h"
#include "memory_scanner.h"
#include "imgui.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

MemoryScanner g_memoryScanner;

// Upper bound of 32-bit user-mode address space.
static const uintptr_t USER_SPACE_END = 0x7FFE0000;

// Safety cap so a broad first scan (e.g. "0" as Int32) cannot exhaust memory.
static const size_t MAX_MATCHES = 2000000;

// Regions are scanned in 1 MB chunks to bound temporary allocations.
static const size_t SCAN_CHUNK_SIZE = 1024 * 1024;

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

size_t MemoryScanner::FirstScan(ScanValueType type, const unsigned char* valueBytes)
{
	m_matches.clear();
	m_valueType = type;

	const size_t valueSize = ScanValueTypeSize(type);
	std::vector<unsigned char> buffer;
	buffer.reserve(SCAN_CHUNK_SIZE);

	uintptr_t address = 0x10000; // skip the null-page region
	MEMORY_BASIC_INFORMATION regionInfo;

	while (address < USER_SPACE_END)
	{
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(address), &regionInfo, sizeof(regionInfo)))
			break;

		uintptr_t regionBase = reinterpret_cast<uintptr_t>(regionInfo.BaseAddress);
		uintptr_t regionEnd = regionBase + regionInfo.RegionSize;

		bool scannable = regionInfo.State == MEM_COMMIT && IsScannableProtection(regionInfo.Protect);

		if (scannable)
		{
			// Overlap chunks by (valueSize - 1) so values crossing a chunk
			// boundary are still found.
			for (uintptr_t chunk = regionBase; chunk < regionEnd; chunk += SCAN_CHUNK_SIZE - (valueSize - 1))
			{
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

					if (memcmp(buffer.data() + i, valueBytes, valueSize) == 0)
					{
						ScanMatch match;
						match.address = chunk + i;
						memset(match.previousValue, 0, sizeof(match.previousValue));
						memcpy(match.previousValue, buffer.data() + i, valueSize);
						m_matches.push_back(match);

						if (m_matches.size() >= MAX_MATCHES)
						{
							m_hasResults = true;
							return m_matches.size();
						}
					}
				}
			}
		}

		if (regionEnd <= regionBase) // overflow safety
			break;
		address = regionEnd;
	}

	m_hasResults = true;
	return m_matches.size();
}

size_t MemoryScanner::NextScan(ScanCompareType compare, const unsigned char* valueBytes)
{
	if (!m_hasResults)
		return 0;

	const size_t valueSize = ScanValueTypeSize(m_valueType);
	std::vector<ScanMatch> filtered;
	filtered.reserve(m_matches.size());

	for (size_t i = 0; i < m_matches.size(); i++)
	{
		unsigned char currentValue[8] = {};
		if (!SafeReadMemory(m_matches[i].address, currentValue, valueSize))
			continue;

		if (CompareDispatch(m_valueType, compare, currentValue, m_matches[i].previousValue, valueBytes))
		{
			ScanMatch match;
			match.address = m_matches[i].address;
			memcpy(match.previousValue, currentValue, sizeof(match.previousValue));
			filtered.push_back(match);
		}
	}

	m_matches.swap(filtered);
	return m_matches.size();
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
	m_matches.clear();
	m_hasResults = false;
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
	static char statusText[160] = "Pick a type, enter a value, press First Scan.";

	static const char* valueTypes[] = { "Int32", "UInt32", "Float", "Double", "Byte", "Int16", "Int64" };
	static const char* compareTypes[] = { "Exact Value", "Changed Value", "Unchanged Value", "Increased Value", "Decreased Value" };

	ScanValueType valueType = static_cast<ScanValueType>(valueTypeIndex);
	size_t valueSize = ScanValueTypeSize(valueType);

	ImGui::PushItemWidth(110);
	int previousTypeIndex = valueTypeIndex;
	ImGui::Combo("Type", &valueTypeIndex, valueTypes, IM_ARRAYSIZE(valueTypes));
	ImGui::SameLine();
	ImGui::Combo("Compare", &compareTypeIndex, compareTypes, IM_ARRAYSIZE(compareTypes));
	ImGui::PopItemWidth();

	// Changing the value type invalidates previous results (sizes differ).
	if (valueTypeIndex != previousTypeIndex)
	{
		g_memoryScanner.Reset();
		selectedMatch = -1;
		valueType = static_cast<ScanValueType>(valueTypeIndex);
		valueSize = ScanValueTypeSize(valueType);
	}

	ImGui::PushItemWidth(180);
	ImGui::InputText("Value", valueInput, sizeof(valueInput));
	ImGui::PopItemWidth();

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
			size_t found = g_memoryScanner.FirstScan(valueType, valueBytes);
			sprintf_s(statusText, "First scan: %u matches%s.", static_cast<unsigned int>(found),
				found >= MAX_MATCHES ? " (capped, refine with Next Scan)" : "");
		}
	}
	ImGui::SameLine();

	if (ImGui::Button("Next Scan"))
	{
		if (!g_memoryScanner.HasScanResults())
		{
			sprintf_s(statusText, "Run a First Scan first.");
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
				size_t found = g_memoryScanner.NextScan(static_cast<ScanCompareType>(compareTypeIndex), valueBytes);
				sprintf_s(statusText, "Next scan: %u matches.", static_cast<unsigned int>(found));
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

	ImGui::TextWrapped("%s", statusText);

	// ---- Results list -----------------------------------------------------
	const std::vector<ScanMatch>& matches = g_memoryScanner.GetMatches();
	const size_t displayLimit = 2000; // keep the list UI responsive
	int displayCount = static_cast<int>(matches.size() < displayLimit ? matches.size() : displayLimit);

	if (matches.size() > displayLimit)
		ImGui::TextWrapped("Showing first %u results. Refine with Next Scan.", static_cast<unsigned int>(displayLimit));

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

	// ---- Write / freeze controls ------------------------------------------
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
