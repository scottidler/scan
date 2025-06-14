use crate::web::dns::{DnsInfo, DnsRecord, MxRecord, TxtRecord, TxtRecordType};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

pub fn draw_dns_tab(f: &mut Frame, area: Rect, dns_info: &DnsInfo) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left column: A, AAAA, NS records
    let mut left_items = Vec::new();

    if !dns_info.a_records.is_empty() {
        left_items.push(ListItem::new(Line::from(vec![
            Span::styled("A Records:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ])));
        for record in &dns_info.a_records {
            left_items.push(ListItem::new(format!("  {}", record.value)));
        }
        left_items.push(ListItem::new(""));
    }

    if !dns_info.aaaa_records.is_empty() {
        left_items.push(ListItem::new(Line::from(vec![
            Span::styled("AAAA Records:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ])));
        for record in &dns_info.aaaa_records {
            left_items.push(ListItem::new(format!("  {}", record.value)));
        }
        left_items.push(ListItem::new(""));
    }

    if !dns_info.ns_records.is_empty() {
        left_items.push(ListItem::new(Line::from(vec![
            Span::styled("NS Records:", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ])));
        for record in &dns_info.ns_records {
            left_items.push(ListItem::new(format!("  {}", record.value)));
        }
    }

    let left_list = List::new(left_items)
        .block(Block::default().borders(Borders::ALL).title("Basic Records"))
        .style(Style::default().fg(Color::White));
    f.render_widget(left_list, chunks[0]);

    // Right column: MX, TXT, other records
    let mut right_items = Vec::new();

    if !dns_info.mx_records.is_empty() {
        right_items.push(ListItem::new(Line::from(vec![
            Span::styled("MX Records:", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        ])));
        for record in &dns_info.mx_records {
            right_items.push(ListItem::new(format!("  {} {}", record.priority, record.exchange)));
        }
        right_items.push(ListItem::new(""));
    }

    if !dns_info.txt_records.is_empty() {
        right_items.push(ListItem::new(Line::from(vec![
            Span::styled("TXT Records:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ])));
        for record in &dns_info.txt_records {
            let truncated = if record.value.len() > 50 {
                format!("{}...", &record.value[..47])
            } else {
                record.value.clone()
            };
            let record_type = match record.record_type {
                TxtRecordType::Spf => "📧 SPF",
                TxtRecordType::Dkim => "🔑 DKIM",
                TxtRecordType::Dmarc => "📝 DMARC",
                TxtRecordType::General => "📄 General",
            };
            right_items.push(ListItem::new(format!("  {}: {}", record_type, truncated)));
        }
    }

    let right_list = List::new(right_items)
        .block(Block::default().borders(Borders::ALL).title("Mail & Text Records"))
        .style(Style::default().fg(Color::White));
    f.render_widget(right_list, chunks[1]);

    // Add resolution time and DNSSEC status at the bottom
    let bottom_area = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area)[1];

    let mut status_lines = vec![];
    status_lines.push(Line::from(vec![
        Span::styled("🕐 Resolution: ", Style::default().fg(Color::Gray)),
        Span::styled(format!("{}ms", dns_info.resolution_time.as_millis()), Style::default().fg(Color::Cyan)),
    ]));

    if let Some(dnssec_valid) = dns_info.dnssec_valid {
        status_lines.push(Line::from(vec![
            Span::styled("🛡️  DNSSEC: ", Style::default().fg(Color::Gray)),
            Span::styled(
                if dnssec_valid { "✓" } else { "✗" },
                Style::default().fg(if dnssec_valid { Color::Green } else { Color::Red }),
            ),
        ]));
    }

    if let Some(doh_support) = dns_info.doh_support {
        status_lines.push(Line::from(vec![
            Span::styled("🔒 DoH: ", Style::default().fg(Color::Gray)),
            Span::styled(
                if doh_support { "✓" } else { "✗" },
                Style::default().fg(if doh_support { Color::Green } else { Color::Red }),
            ),
        ]));
    }

    let status = Paragraph::new(status_lines)
        .block(Block::default().borders(Borders::ALL).title("DNS Status"))
        .wrap(Wrap { trim: true });
    f.render_widget(status, bottom_area);
}
