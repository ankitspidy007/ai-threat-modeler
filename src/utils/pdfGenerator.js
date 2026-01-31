import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';

export const generateReport = async (data, projectName) => {
    console.log("PDF Data:", data);
    try {
        if (!data) {
            alert("No data to export.");
            return;
        }

        const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
        const pageWidth = doc.internal.pageSize.getWidth();
        const pageHeight = doc.internal.pageSize.getHeight();
        let yPos = 20;
        const leftMargin = 15;
        const rightMargin = 15;
        const contentWidth = pageWidth - leftMargin - rightMargin;
        const lineHeight = 5;

        // Separate threats by tier
        const confirmed = data.threats?.filter(t => t.tier === 'Confirmed') || [];
        const potential = data.threats?.filter(t => t.tier === 'Potential') || [];

        // --- Helpers ---
        const addText = (text, size = 10, style = 'normal', color = [0, 0, 0]) => {
            if (!text) return;
            doc.setFontSize(size);
            doc.setFont('helvetica', style);
            doc.setTextColor(...color);
            const lines = doc.splitTextToSize(String(text), contentWidth);
            doc.text(lines, leftMargin, yPos);
            yPos += lines.length * lineHeight;
            checkPageBreak();
        };

        const addHeading = (text, size = 14, color = [44, 62, 80]) => {
            yPos += 6;
            addText(text, size, 'bold', color);
            doc.setDrawColor(200, 200, 200);
            doc.line(leftMargin, yPos - 2, pageWidth - rightMargin, yPos - 2);
            yPos += 4;
        };

        const checkPageBreak = (buffer = 25) => {
            if (yPos > pageHeight - buffer) {
                doc.addPage();
                yPos = 20;
            }
        };

        // =============================================
        // HEADER
        // =============================================
        doc.setFillColor(44, 62, 80);
        doc.rect(0, 0, pageWidth, 30, 'F');

        doc.setTextColor(255, 255, 255);
        doc.setFontSize(18);
        doc.setFont('helvetica', 'bold');
        doc.text("THREAT MODEL REPORT", leftMargin, 15);

        doc.setFontSize(11);
        doc.setFont('helvetica', 'normal');
        doc.text(projectName || "Untitled Project", leftMargin, 23);

        // Score badge
        const scoreColor = (data.score || 0) >= 70 ? [39, 174, 96] : (data.score || 0) >= 40 ? [241, 196, 15] : [231, 76, 60];
        doc.setFillColor(...scoreColor);
        doc.roundedRect(pageWidth - 45, 8, 35, 18, 2, 2, 'F');
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(14);
        doc.setFont('helvetica', 'bold');
        doc.text(`${data.score || 0}/100`, pageWidth - 42, 20);

        yPos = 40;

        // Summary
        doc.setTextColor(0, 0, 0);
        addText(`Summary: ${data.summary}`, 10);
        addText(`Unique Threats: ${data.threats?.length || 0} (${confirmed.length} confirmed, ${potential.length} potential)`, 9, 'normal', [100, 100, 100]);
        yPos += 3;

        // =============================================
        // ARCHITECTURE
        // =============================================
        addHeading("1. System Architecture");

        // Capture diagram
        const mermaidElement = document.querySelector('#graphDiv, [class*="mermaid"] svg');
        if (mermaidElement) {
            try {
                const container = mermaidElement.closest('div');
                if (container) {
                    const canvas = await html2canvas(container, { scale: 2, backgroundColor: '#ffffff' });
                    const imgData = canvas.toDataURL('image/png');
                    const imgWidth = contentWidth * 0.8;
                    const imgHeight = (canvas.height * imgWidth) / canvas.width;
                    checkPageBreak(imgHeight + 10);
                    doc.addImage(imgData, 'PNG', leftMargin + 10, yPos, imgWidth, Math.min(imgHeight, 60));
                    yPos += Math.min(imgHeight, 60) + 5;
                }
            } catch (e) { console.warn("Diagram capture failed", e); }
        }

        // Components
        if (data.architecture?.components?.length) {
            addText("Components:", 10, 'bold');
            data.architecture.components.forEach(c => addText(`  • ${c.name} (${c.type})`, 9));
        }

        if (data.architecture?.flows?.length) {
            addText("Data Flows:", 10, 'bold');
            data.architecture.flows.slice(0, 5).forEach(f => addText(`  • ${f.source_id} → ${f.target_id}`, 9));
            if (data.architecture.flows.length > 5) addText(`  ... and ${data.architecture.flows.length - 5} more`, 8, 'italic', [128, 128, 128]);
        }

        // =============================================
        // CONFIRMED RISKS
        // =============================================
        addHeading("2. Confirmed Risks", 14, [39, 174, 96]);

        if (confirmed.length === 0) {
            addText("No confirmed risks detected.", 10, 'italic', [100, 100, 100]);
        } else {
            confirmed.forEach(t => renderThreat(doc, t, leftMargin, contentWidth, checkPageBreak, () => yPos, (v) => yPos = v));
        }

        // =============================================
        // POTENTIAL RISKS
        // =============================================
        addHeading("3. Potential Risks (Assumption-Based)", 14, [241, 196, 15]);

        if (potential.length === 0) {
            addText("No potential risks detected.", 10, 'italic', [100, 100, 100]);
        } else {
            potential.forEach(t => renderThreat(doc, t, leftMargin, contentWidth, checkPageBreak, () => yPos, (v) => yPos = v));
        }

        // =============================================
        // FOOTER
        // =============================================
        const pageCount = doc.internal.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            doc.setFontSize(8);
            doc.setTextColor(150, 150, 150);
            doc.text(`Page ${i} of ${pageCount}`, pageWidth - 30, pageHeight - 10);
            doc.text("AI Threat Modeler", leftMargin, pageHeight - 10);
        }

        doc.save(`${(projectName || 'Threat_Report').replace(/\s+/g, '_')}.pdf`);

        function renderThreat(doc, t, leftMargin, contentWidth, checkPageBreak, getY, setY) {
            let y = getY();
            checkPageBreak(50);
            y = getY();

            // Severity color
            const sevColors = { Critical: [231, 76, 60], High: [230, 126, 34], Medium: [241, 196, 15], Low: [52, 152, 219] };
            const sevColor = sevColors[t.severity] || [100, 100, 100];

            // Header bar
            doc.setFillColor(...sevColor);
            doc.roundedRect(leftMargin, y - 4, contentWidth, 7, 1, 1, 'F');
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(9);
            doc.setFont('helvetica', 'bold');
            doc.text(`[${t.severity}] ${t.title}`.substring(0, 80), leftMargin + 2, y);
            y += 9;
            setY(y);

            // Meta
            doc.setTextColor(100, 100, 100);
            doc.setFontSize(8);
            doc.setFont('helvetica', 'normal');
            doc.text(`${t.category} | Confidence: ${t.confidence}`, leftMargin, y);
            y += 5;
            setY(y);

            // Description
            doc.setTextColor(50, 50, 50);
            doc.setFontSize(9);
            const descLines = doc.splitTextToSize(t.description || '', contentWidth - 5);
            doc.text(descLines.slice(0, 3), leftMargin, y);
            y += descLines.slice(0, 3).length * 4 + 2;
            setY(y);

            // Affected
            if (t.affected_components?.length) {
                doc.setFontSize(8);
                doc.setFont('helvetica', 'bold');
                doc.text("Affected: ", leftMargin, y);
                doc.setFont('helvetica', 'normal');
                doc.text(t.affected_components.join(', ').substring(0, 60), leftMargin + 15, y);
                y += 4;
                setY(y);
            }

            // Mitigation
            doc.setFillColor(232, 245, 233);
            doc.roundedRect(leftMargin, y - 2, contentWidth, 10, 1, 1, 'F');
            doc.setFontSize(8);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(39, 174, 96);
            doc.text("Mitigation:", leftMargin + 2, y + 3);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(30, 30, 30);
            const mitLines = doc.splitTextToSize(t.mitigation || 'N/A', contentWidth - 25);
            doc.text(mitLines[0] || '', leftMargin + 22, y + 3);
            y += 14;
            setY(y);
        }

    } catch (error) {
        console.error("PDF Generation Error:", error);
        alert(`PDF generation failed: ${error.message}`);
    }
};
