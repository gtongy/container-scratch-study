// +build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Unsetter func() error

func SetupNetwork(bridge string) (error, error){
	digest := "digest"
	nsMountTarget := filepath.Join("/gtongy/netns", digest)
	vethName := fmt.Sprintf("veth%.7s", digest)
	peerName := fmt.Sprintf("P%s", vethName)
	if err := SetupVirtualEthernet(vethName, peerName); err != nil {
		return nil, err
	}
	if err := LinkSetMaster(vethName, bridge); err != nil {
		return nil, err
	}
	unmount, err := MountNetworkNamespace(nsMountTarget)
	if err != nil {
		return unmount, err
	}
	if err := LinkSetNsByFile(nsMountTarget, peerName); err != nil {
		return unmount, nil
	}
	// Change current network namespace to setup the veth
	unset, err := SetNetNSByFile(nsMountTarget)
	if err != nil {
		return unmount, err
	}
	defer unset()
	return nil, nil
}

func SetupVirtualEthernet(name, peer string) error {
	linkAttrs := netlink.NewLinkAttrs()
	linkAttrs.Name = name
	vth := &netlink.Veth{
		LinkAttrs: linkAttrs,
		PeerName:  peer,
	}
	if err := netlink.LinkAdd(vth); err != nil {
		return err
	}
	return netlink.LinkSetUp(vth)
}

// LinkSetMaster setup bridge and veth
func LinkSetMaster(linkName, masterName string) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return errors.Wrapf(err, "can not find link %s", linkName)
	}
	masterLink, err := netlink.LinkByName(masterName)
	if err != nil {
		return errors.Wrapf(err, "can not find link %s", masterName)
	}
	if err := netlink.LinkSetMaster(link, masterLink); err != nil {
		return err
	}
	return nil
}

// MountNetworkNamespace mount network to last lifetime.
func MountNetworkNamespace(nsTarget string) (error, error) {
	_, err := os.OpenFile(nsTarget, syscall.O_RDONLY|syscall.O_CREAT|syscall.O_EXCL, 0644)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create target file")
	}
	file, err := os.OpenFile("/proc/self/ns/net", os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		return nil, errors.Wrap(err, "unshare syscall failed")
	}
	// TODO: mount file
	if err := unix.Setns(int(file.Fd()), syscall.CLONE_NEWNET); err != nil {
		// TODO: return unmount
		return nil, error.Wrap(err, "setns syscall failed")
	}
	// TODO: return unmount
	return nil, err
}

func LinkSetNsByFile(filename, linkName string) error {
	netnsFile, err := os.OpenFile(filename, syscall.O_RDONLY, 0)
	if err != nil {
		return errors.Wrap(err, "unable to open netns file")
	}
	defer netnsFile.Close()
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}
	// puts the device into a new network namespace
	return netlink.LinkSetNsFd(link, int(netnsFile.Fd()))
}

func SetNetNSByFile(filename string) (Unsetter, error) {
	currentNS, err := os.OpenFile("/proc/self/ns/net", os.O_RDONLY, 0)
	unsetFunc := func() error {
		defer currentNS.Close()
		if err != nil {
			return err
		}
		return unix.Setns(int(currentNS.Fd()), syscall.CLONE_NEWNET)
	}
	netnsFile, err := os.OpenFile(filename, syscall.O_RDONLY, 0)
	if err != nil {
		return unsetFunc, errors.Wrap(err, "unable to open network namespace file")
	}
	defer netnsFile.Close()
	if err := unix.Setns(int(netnsFile.Fd()), syscall.CLONE_NEWNET); err != nil {
		return unsetFunc, errors.Wrap(err, "unset syscall failed")
	}
	return unsetFunc, err
}
