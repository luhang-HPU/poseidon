#include "omp_trace.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <unordered_map>

#if defined(_OPENMP) || defined(POSEIDON_USE_OPENMP) || defined(USING_OPENMP)
#include <omp.h>
#endif

#ifdef __linux__
#include <sched.h>
#endif

namespace poseidon
{
namespace util
{
namespace omp_trace
{

namespace
{

struct RegionRecord
{
    std::set<int> omp_threads;
    std::set<int> omp_places;
    std::set<int> cpu_cores;
    std::size_t hits = 0;
    int max_team_size = 0;
    int max_level = 0;
};

std::mutex &trace_mutex()
{
    static std::mutex mutex;
    return mutex;
}

std::unordered_map<std::string, RegionRecord> &trace_map()
{
    static std::unordered_map<std::string, RegionRecord> records;
    return records;
}

bool compute_enabled()
{
    const char *value = std::getenv("POSEIDON_TRACE_OMP_CORES");
    if (!value)
    {
        return false;
    }

    const std::string str(value);
    return !(str.empty() || str == "0" || str == "false" || str == "FALSE");
}

int current_cpu_id()
{
#ifdef __linux__
    return sched_getcpu();
#else
    return -1;
#endif
}

}  // namespace

bool enabled()
{
    static const bool is_enabled = compute_enabled();
    return is_enabled;
}

void clear()
{
    if (!enabled())
    {
        return;
    }

    std::lock_guard<std::mutex> lock(trace_mutex());
    trace_map().clear();
}

void record(const char *region)
{
    if (!enabled() || region == nullptr || region[0] == '\0')
    {
        return;
    }

    int omp_thread = 0;
    int omp_place = -1;
    int omp_team_size = 1;
    int omp_level = 0;

#if defined(_OPENMP) || defined(POSEIDON_USE_OPENMP) || defined(USING_OPENMP)
    if (omp_in_parallel())
    {
        omp_thread = omp_get_thread_num();
        omp_team_size = omp_get_num_threads();
        omp_level = omp_get_level();
#if defined(_OPENMP) && _OPENMP >= 201307
        omp_place = omp_get_place_num();
#endif
    }
#endif

    const int cpu = current_cpu_id();

    std::lock_guard<std::mutex> lock(trace_mutex());
    auto &record = trace_map()[region];
    record.hits += 1;
    record.omp_threads.insert(omp_thread);
    if (omp_place >= 0)
    {
        record.omp_places.insert(omp_place);
    }
    if (cpu >= 0)
    {
        record.cpu_cores.insert(cpu);
    }
    record.max_team_size = std::max(record.max_team_size, omp_team_size);
    record.max_level = std::max(record.max_level, omp_level);
}

std::vector<RegionSnapshot> snapshot()
{
    std::vector<RegionSnapshot> out;
    if (!enabled())
    {
        return out;
    }

    std::lock_guard<std::mutex> lock(trace_mutex());
    out.reserve(trace_map().size());
    for (const auto &entry : trace_map())
    {
        out.push_back(
            {entry.first,
             entry.second.omp_threads,
             entry.second.omp_places,
             entry.second.cpu_cores,
             entry.second.hits,
             entry.second.max_team_size,
             entry.second.max_level});
    }

    std::sort(out.begin(), out.end(), [](const RegionSnapshot &lhs, const RegionSnapshot &rhs) {
        return lhs.name < rhs.name;
    });
    return out;
}

void print_report(std::ostream &os, const std::string &title)
{
    if (!enabled())
    {
        return;
    }

    const auto regions = snapshot();

    os << title << std::endl;
    if (regions.empty())
    {
        os << "  (no internal OpenMP activity recorded)" << std::endl;
        return;
    }

    for (const auto &region : regions)
    {
        os << "  [libomp] " << region.name << std::endl;

        os << "    omp_threads: ";
        if (region.omp_threads.empty())
        {
            os << "(none)";
        }
        else
        {
            bool first = true;
            for (int tid : region.omp_threads)
            {
                if (!first)
                {
                    os << ",";
                }
                os << tid;
                first = false;
            }
        }
        os << std::endl;

        os << "    omp_places: ";
        if (region.omp_places.empty())
        {
            os << "(unavailable)";
        }
        else
        {
            bool first = true;
            for (int place : region.omp_places)
            {
                if (!first)
                {
                    os << ",";
                }
                os << place;
                first = false;
            }
        }
        os << std::endl;

        os << "    cpu_cores: ";
        if (region.cpu_cores.empty())
        {
            os << "(unavailable)";
        }
        else
        {
            bool first = true;
            for (int cpu : region.cpu_cores)
            {
                if (!first)
                {
                    os << ",";
                }
                os << cpu;
                first = false;
            }
        }
        os << std::endl;

        os << "    hits: " << region.hits << ", max_team_size: " << region.max_team_size
           << ", max_level: " << region.max_level << std::endl;
    }
}

}  // namespace omp_trace
}  // namespace util
}  // namespace poseidon
