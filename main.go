package main

import (
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
	return lipgloss.JoinVertical(
		lipgloss.Left,
		"gotyour",
		baseStyle.Render(m.table.View()),
		baseStyle.Render(m.viewport.View()),
	)
}

func main() {
	packetChan := make(chan gopacket.Packet)

	go func() {
		device := "wlp15s0"
		snapshotLen := int32(1024)
		promiscuous := true
		timeout := 30 * time.Second

		handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
		if err != nil {
			log.Fatal(err)
		}
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
	vp.SetContent("Listening for packets...")

	m := model{
		table: t,
		viewport: vp,
		packets: make([]gopacket.Packet, 0),
		sub: packetChan,
	}

	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Printf("Error running gotyour: %v\n", err)
		os.Exit(1)
	}
}
