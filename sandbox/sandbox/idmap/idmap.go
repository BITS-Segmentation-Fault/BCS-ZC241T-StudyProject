package idmap

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

type IDRange struct {
	StartID int
	Count   int
}

type Mapping struct {
	ContainerID int
	HostID      int
	Count       int
}

func ReadSubIDRanges(path string, targetUser string) ([]IDRange, error) {
	var ranges []IDRange
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %v", path, err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			continue
		}

		if parts[0] != targetUser {
			continue
		}

		start, err1 := strconv.Atoi(parts[1])
		count, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil || start < 0 || count <= 0 {
			return nil, fmt.Errorf("invalid numeric value or range in %s: %s", path, line)
		}

		ranges = append(ranges, IDRange{StartID: start, Count: count})
	}

	if len(ranges) == 0 {
		return nil, fmt.Errorf("no subid entries for user '%s' in %s", targetUser, path)
	}

	return ranges, nil
}

func BuildIDMap(hostID int, subidRanges []IDRange) []Mapping {
	maps := []Mapping{{ContainerID: 0, HostID: hostID, Count: 1}}
	nextContainerID := 1
	for _, r := range subidRanges {
		maps = append(maps, Mapping{
			ContainerID: nextContainerID,
			HostID:      r.StartID,
			Count:       r.Count,
		})
		nextContainerID += r.Count
	}
	return maps
}

func WriteIDMaps(childPID, hostUID, hostGID int) error {
	procPath := fmt.Sprintf("/proc/%d", childPID)

	if _, err := os.Stat(procPath); os.IsNotExist(err) && filepath.Separator == '\\' {
		return nil
	}

	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("failed to look up current system user: %v", err)
	}

	subUIDs, err := ReadSubIDRanges("/etc/subuid", currentUser.Username)
	if err != nil {
		return err
	}
	subGIDs, err := ReadSubIDRanges("/etc/subgid", currentUser.Username)
	if err != nil {
		return err
	}

	uidMap := BuildIDMap(hostUID, subUIDs)
	gidMap := BuildIDMap(hostGID, subGIDs)

	setGroupsPath := filepath.Join(procPath, "setgroups")
	if _, err := os.Stat(setGroupsPath); err == nil {
		if err := os.WriteFile(setGroupsPath, []byte("deny\n"), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %v", setGroupsPath, err)
		}
	}

	if err := runIDMapHelper("newuidmap", childPID, uidMap); err != nil {
		return err
	}
	return runIDMapHelper("newgidmap", childPID, gidMap)
}

func runIDMapHelper(helper string, childPID int, mappings []Mapping) error {
	helperPath, err := exec.LookPath(helper)
	if err != nil {
		return fmt.Errorf("%s not found in PATH", helper)
	}

	args := []string{strconv.Itoa(childPID)}
	for _, m := range mappings {
		args = append(args, strconv.Itoa(m.ContainerID), strconv.Itoa(m.HostID), strconv.Itoa(m.Count))
	}

	cmd := exec.Command(helperPath, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s failed: %s (%v)", helper, strings.TrimSpace(string(output)), err)
	}
	return nil
}
