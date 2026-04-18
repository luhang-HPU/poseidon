#pragma once

#include <iosfwd>
#include <set>
#include <string>
#include <vector>

namespace poseidon
{
namespace util
{
namespace omp_trace
{

struct RegionSnapshot
{
    std::string name;
    std::set<int> omp_threads;
    std::set<int> omp_places;
    std::set<int> cpu_cores;
    std::size_t hits = 0;
    int max_team_size = 0;
    int max_level = 0;
};

bool enabled();
void clear();
void record(const char *region);
std::vector<RegionSnapshot> snapshot();
void print_report(std::ostream &os, const std::string &title);

}  // namespace omp_trace
}  // namespace util
}  // namespace poseidon
