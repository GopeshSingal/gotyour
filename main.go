package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

type packetMsg struct {
	packet gopacket.Packet
}

type model struct {
	table 	 table.Model
	viewport viewport.Model
	packets  []gopacket.Packet
	sub		 chan gopacket.Packet
	device   string
	filter   string
	paused   bool
}

func listenPackets(sub chan gopacket.Packet) tea.Cmd {
	return func() tea.Msg {
		return packetMsg{<-sub}
	}
}

func (m model) Init() tea.Cmd {
	return listenPackets(m.sub)
}

func (m *model) updateDetailView() {
	if len(m.packets) == 0 {
		return
	}

	selectedIdx := m.table.Cursor()
	if selectedIdx < 0 || selectedIdx >= len(m.packets) {
		return
	}

	selectedPkt := m.packets[selectedIdx]

	dump := fmt.Sprintf("--- packet dump ---\n%s", selectedPkt.Dump())
	m.viewport.SetContent(dump)
}

func parsePacketSummary(packet gopacket.Packet) (src, dst, proto, length string) {
	length = fmt.Sprintf("%d B", len(packet.Data()))
	proto = "RAW"

	if netLayer := packet.NetworkLayer(); netLayer != nil {
		src = netLayer.NetworkFlow().Src().String()
		dst = netLayer.NetworkFlow().Dst().String()
	}
	
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		proto = transportLayer.LayerType().String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		proto = "IPv4"
	}

	return src, dst, proto, length
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}

	case packetMsg:
		pkt := msg.packet
		m.packets = append(m.packets, pkt)

		src, dst, proto, length := parsePacketSummary(pkt)

		newRow := table.Row{
			time.Now().Format("15:04:05"),
			proto,
			src,
			dst,
			length,
		}

		rows := append(m.table.Rows(), newRow)
		if len(rows) > 500 {
			rows = rows[1:]
			m.packets = m.packets[1:]
		}
		m.table.SetRows(rows)

		m.updateDetailView()

		return m, listenPackets(m.sub)
	}

	var tableCmd tea.Cmd
	m.table, tableCmd = m.table.Update(msg)
	cmds = append(cmds, tableCmd)

	if _, ok := msg.(tea.KeyMsg); ok {
		m.updateDetailView()
	}

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	status := fmt.Sprintf("gotyour | %s", m.device)
	if m.filter != "" {
		status += fmt.Sprintf(" | filter: %s", m.filter)
	}
	if m.paused {
		status += " | PAUSED"
	}
	return lipgloss.JoinVertical(
		lipgloss.Left,
		"gotyour",
		baseStyle.Render(m.table.View()),
		baseStyle.Render(m.viewport.View()),
	)
}

func pickDefaultDevice(devs []pcap.Interface) string {
	for _, d := range devs {
		if d.Name == "lo" {
			continue
		}
		for _, addr := range d.Addresses {
			if addr.IP != nil && !addr.IP.IsLoopback() {
				return d.Name
			}
		}
	}

	for _, d := range devs {
		if d.Name != "lo" {
			return d.Name
		}
	}

	if len(devs) > 0 {
		return devs[0].Name
	}

	return ""
}

func resolveInterface(name string) (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("enumerate devices: %w", err)
	}
	if len(devs) == 0 {
		return "", fmt.Errorf("no capture devices found")
	}

	if name != "" {
		for _, d := range devs {
			if d.Name == name {
				return d.Name, nil
			}
		}
		return "", fmt.Errorf("interface %q not found (use -l to list)", name)
	}
	if picked := pickDefaultDevice(devs); picked != "" {
		return picked, nil
	}
	return "", fmt.Errorf("no suitable default interface found")
}

func listInterfaces() error {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}
	for _, d := range devs {
		fmt.Printf("%s\n", d.Name)
		if d.Description != "" {
			fmt.Printf("  %s\n", d.Description)
		}
		for _, addr := range d.Addresses {
			fmt.Printf("  %s\n", addr.IP)
		}
	}
	return nil
}

func main() {
	ifaceFlag := flag.String("i", "", "network interface to capture on")
	listFlag := flag.Bool("l", false, "list available interfaces and exit")
	filterFlag := flag.String("f", "", "BPF filter expression")
	flag.Parse()

	if *listFlag {
		if err := listInterfaces(); err != nil {
			fmt.Fprintf(os.Stderr, "gotyour: %v\n", err)
			os.Exit(1)
		}
		return
	}

	dev, err := resolveInterface(*ifaceFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gotyour: %v\n", err)
		os.Exit(1)
	}

	snapshotLen := int32(1024)
	promiscuous := true
	timeout := 30 * time.Second

	handle, err := pcap.OpenLive(dev, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}

	if *filterFlag != "" {
		if err := handle.SetBPFFilter(*filterFlag); err != nil {
			handle.Close()
			fmt.Fprintf(os.Stderr, "gotyour: invalid BPF filter: %v\n", err)
			os.Exit(1)
		}
	}

	packetChan := make(chan gopacket.Packet)

	go func() {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for pkt := range packetSource.Packets() {
			packetChan <- pkt
		}
	}()

	cols := []table.Column{
		{Title: "Time", Width: 10},
		{Title: "Proto", Width: 8},
		{Title: "Src", Width: 18},
		{Title: "Dst", Width: 18},
		{Title: "Length", Width: 8},
	}

	t := table.New(
		table.WithColumns(cols),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).
		Bold(true)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(true)
	t.SetStyles(s)

	vp := viewport.New(70, 12)
	vp.SetContent(fmt.Sprintf("Listening on %s...", dev))

	m := model{
		table: t,
		viewport: vp,
		packets: make([]gopacket.Packet, 0),
		sub: packetChan,
		device: dev,
		filter: *filterFlag,
	}

	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Printf("Error running gotyour: %v\n", err)
		os.Exit(1)
	}
}
