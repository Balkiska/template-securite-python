import os
import tempfile
import pygal
from fpdf import FPDF
from tp1.utils.config import logger


class Report:
    def __init__(self, capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "IDS/IPS - Network Analysis Report"
        self.summary = summary
        self.array_data = []    # list of row tuples
        self.graph_path = ""    # path to generated chart image

    def generate(self, param: str) -> None:
        """Generate either a graph or an array from capture data."""
        if param == "graph":
            self._generate_graph()
        elif param == "array":
            self._generate_array()

    def _generate_graph(self) -> None:
        """Create a Pygal bar chart of protocol distribution and save as PNG."""
        stats = self.capture.protocol_stats
        if not stats:
            logger.warning("No protocol stats to graph")
            return

        pink_style = pygal.style.Style(colors=["#FFB6C1"])
        chart = pygal.Bar(
            title="Captured Network Protocols",
            x_title="Protocol",
            y_title="Packet Count",
            style=pink_style,
            print_values=True,
        )
        sorted_protos = sorted(stats.items(), key=lambda x: x[1], reverse=True)
        chart.x_labels = [p for p, _ in sorted_protos]
        chart.add("Packets", [c for _, c in sorted_protos])

        # save as PNG for PDF embedding
        self.graph_path = os.path.join(tempfile.gettempdir(), "tp1_chart.png")
        chart.render_to_png(self.graph_path)
        logger.info(f"Graph saved to {self.graph_path}")

    def _generate_array(self) -> None:
        """Build table rows: protocol, count, legitimacy status."""
        stats = self.capture.protocol_stats
        alerts = self.capture.alerts
        # build set of protocols involved in alerts
        alert_protocols = {a["protocol"] for a in alerts}

        sorted_protos = sorted(stats.items(), key=lambda x: x[1], reverse=True)
        self.array_data = []
        for proto, count in sorted_protos:
            status = "Suspicious" if proto in alert_protocols else "Legitimate"
            self.array_data.append((proto, str(count), status))
        logger.info(f"Table built with {len(self.array_data)} rows")

    # THE output

    def save(self, filename: str) -> None:
        """Generate and save the final PDF report."""
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # title
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(255, 182, 193)
        pdf.cell(0, 15, self.title, new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)

        # summary
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 6, f"Packets captured: {len(self.capture.packets)}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        # graph
        if self.graph_path and os.path.exists(self.graph_path):
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Protocol Chart", new_x="LMARGIN", new_y="NEXT")
            pdf.image(self.graph_path, x=15, w=180)
            pdf.ln(5)

        # table
        if self.array_data:
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Protocol Table", new_x="LMARGIN", new_y="NEXT")

            # table header
            pdf.set_font("Helvetica", "B", 10)
            col_widths = [70, 40, 70]
            headers = ["Protocol", "Packets", "Status"]
            for header, w in zip(headers, col_widths):
                pdf.cell(w, 8, header, border=1, align="C")
            pdf.ln()

            # table rows
            pdf.set_font("Helvetica", "", 10)
            for proto, count, status in self.array_data:
                pdf.cell(col_widths[0], 7, proto, border=1)
                pdf.cell(col_widths[1], 7, count, border=1, align="C")
                pdf.cell(col_widths[2], 7, status, border=1, align="C")
                pdf.ln()
            pdf.ln(5)

        # alerts section
        alerts = self.capture.alerts
        if alerts:
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Security Alerts", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)
            for alert in alerts:
                pdf.set_text_color(200, 0, 0)
                pdf.cell(0, 6, f"[{alert['type']}] {alert['detail']}", new_x="LMARGIN", new_y="NEXT")
                if alert["attacker_ip"]:
                    pdf.cell(0, 6, f"  IP: {alert['attacker_ip']}", new_x="LMARGIN", new_y="NEXT")
                if alert["attacker_mac"]:
                    pdf.cell(0, 6, f"  MAC: {alert['attacker_mac']}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
        else:
            pdf.set_font("Helvetica", "B", 12)
            pdf.set_text_color(255, 182, 193)
            pdf.cell(0, 10, "No detected threats.", new_x="LMARGIN", new_y="NEXT", align="C")
            pdf.set_text_color(0, 0, 0)

        pdf.output(filename)
        logger.info(f"Report saved to {filename}")
