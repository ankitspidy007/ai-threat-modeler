import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import mermaid from 'mermaid';

export const generateReport = async (data, projectName) => {
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
        const allThreats = data.threats || [];

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
            checkPageBreak(20);
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
        // COVER / HEADER
        // =============================================
        doc.setFillColor(44, 62, 80);
        doc.rect(0, 0, pageWidth, 35, 'F');

        doc.setTextColor(255, 255, 255);
        doc.setFontSize(20);
        doc.setFont('helvetica', 'bold');
        doc.text("THREAT MODEL REPORT", leftMargin, 16);

        doc.setFontSize(11);
        doc.setFont('helvetica', 'normal');
        doc.text(projectName || "Untitled Project", leftMargin, 24);

        doc.setFontSize(8);
        doc.text(`Generated: ${new Date().toLocaleString()}`, leftMargin, 31);

        // Score badge
        const scoreColor = (data.score || 0) >= 70 ? [39, 174, 96] : (data.score || 0) >= 40 ? [241, 196, 15] : [231, 76, 60];
        doc.setFillColor(...scoreColor);
        doc.roundedRect(pageWidth - 50, 8, 40, 22, 3, 3, 'F');
        doc.setTextColor(255, 255, 255);
        doc.setFontSize(16);
        doc.setFont('helvetica', 'bold');
        doc.text(`${data.score || 0}/100`, pageWidth - 46, 19);
        doc.setFontSize(7);
        doc.setFont('helvetica', 'normal');
        doc.text('Security Score', pageWidth - 46, 26);

        yPos = 45;

        // =============================================
        // EXECUTIVE SUMMARY
        // =============================================
        addHeading("1. Executive Summary");
        addText(data.summary || '', 10);
        yPos += 2;

        // Stats boxes
        const statsY = yPos;
        const boxW = contentWidth / 4 - 3;

        const drawStatBox = (x, label, value, bgColor) => {
            doc.setFillColor(...bgColor);
            doc.roundedRect(x, statsY, boxW, 18, 2, 2, 'F');
            doc.setFontSize(14);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(255, 255, 255);
            doc.text(String(value), x + boxW / 2, statsY + 8, { align: 'center' });
            doc.setFontSize(7);
            doc.setFont('helvetica', 'normal');
            doc.text(label, x + boxW / 2, statsY + 14, { align: 'center' });
        };

        const critCount = allThreats.filter(t => t.severity === 'Critical').length;
        const highCount = allThreats.filter(t => t.severity === 'High').length;
        const medCount = allThreats.filter(t => t.severity === 'Medium').length;
        const lowCount = allThreats.filter(t => t.severity === 'Low').length;

        drawStatBox(leftMargin, 'Critical', critCount, [231, 76, 60]);
        drawStatBox(leftMargin + boxW + 4, 'High', highCount, [230, 126, 34]);
        drawStatBox(leftMargin + (boxW + 4) * 2, 'Medium', medCount, [241, 196, 15]);
        drawStatBox(leftMargin + (boxW + 4) * 3, 'Low', lowCount, [52, 152, 219]);

        yPos = statsY + 24;
        addText(`Total: ${allThreats.length} threats (${confirmed.length} confirmed, ${potential.length} potential)`, 9, 'normal', [100, 100, 100]);

        // =============================================
        // RISK ASSESSMENT MATRIX
        // =============================================
        addHeading("2. Risk Assessment Matrix");

        const matrixData = {
            High: { High: 0, Medium: 0, Low: 0 },
            Medium: { High: 0, Medium: 0, Low: 0 },
            Low: { High: 0, Medium: 0, Low: 0 },
        };
        allThreats.forEach(t => {
            const sev = t.severity === 'Critical' ? 'High' : t.severity;
            const lik = t.likelihood || 'Medium';
            if (matrixData[sev] && matrixData[sev][lik] !== undefined) {
                matrixData[sev][lik]++;
            }
        });

        const matrixX = leftMargin + 20;
        const matrixY = yPos;
        const cellW = 28;
        const cellH = 14;
        const labelW = 18;

        const getCellColor = (impact, likelihood) => {
            if (impact === 'High') {
                if (likelihood === 'High') return [231, 76, 60];
                if (likelihood === 'Medium') return [230, 126, 34];
                return [241, 196, 15];
            }
            if (impact === 'Medium') {
                if (likelihood === 'High') return [230, 126, 34];
                if (likelihood === 'Medium') return [241, 196, 15];
                return [241, 220, 100];
            }
            return [39, 174, 96];
        };

        // Column headers
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(80, 80, 80);
        ['Low', 'Medium', 'High'].forEach((label, i) => {
            doc.text(label, matrixX + labelW + i * cellW + cellW / 2, matrixY, { align: 'center' });
        });

        // Y-axis label
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text('IMPACT', matrixX - 5, matrixY + (cellH * 1.5) + 4, { angle: 90 });

        // Rows
        const impacts = ['High', 'Medium', 'Low'];
        impacts.forEach((impact, row) => {
            const rowY = matrixY + 4 + row * cellH;

            // Row label
            doc.setFontSize(8);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(80, 80, 80);
            doc.text(impact, matrixX + labelW - 2, rowY + cellH / 2 + 1, { align: 'right' });

            // Cells
            ['Low', 'Medium', 'High'].forEach((likelihood, col) => {
                const x = matrixX + labelW + col * cellW;
                const count = matrixData[impact]?.[likelihood] || 0;
                const color = getCellColor(impact, likelihood);

                if (count > 0) {
                    doc.setFillColor(...color);
                } else {
                    // Lighter version for empty cells
                    doc.setFillColor(
                        Math.min(color[0] + 100, 240),
                        Math.min(color[1] + 100, 240),
                        Math.min(color[2] + 100, 240)
                    );
                }
                doc.roundedRect(x + 1, rowY, cellW - 2, cellH - 1, 1, 1, 'F');

                if (count > 0) {
                    doc.setFontSize(12);
                    doc.setFont('helvetica', 'bold');
                    doc.setTextColor(255, 255, 255);
                    doc.text(String(count), x + cellW / 2, rowY + cellH / 2 + 1, { align: 'center' });
                }
            });
        });

        // X-axis label
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(80, 80, 80);
        doc.text('LIKELIHOOD', matrixX + labelW + (cellW * 1.5), matrixY + 4 + 3 * cellH + 5, { align: 'center' });

        yPos = matrixY + 4 + 3 * cellH + 12;

        // =============================================
        // STRIDE DISTRIBUTION
        // =============================================
        addHeading("3. STRIDE Threat Distribution");

        const strideCategories = [
            { key: 'Spoofing', color: [231, 76, 60], label: 'S' },
            { key: 'Tampering', color: [230, 126, 34], label: 'T' },
            { key: 'Repudiation', color: [241, 196, 15], label: 'R' },
            { key: 'Information Disclosure', color: [52, 152, 219], label: 'I' },
            { key: 'Denial of Service', color: [142, 68, 173], label: 'D' },
            { key: 'Elevation of Privilege', color: [231, 76, 137], label: 'E' },
        ];

        const strideCounts = {};
        strideCategories.forEach(c => { strideCounts[c.key] = 0; });
        allThreats.forEach(t => {
            const cat = t.stride_category || t.category;
            const match = strideCategories.find(c =>
                cat?.toLowerCase().includes(c.key.toLowerCase().split(' ')[0])
            );
            if (match) strideCounts[match.key]++;
        });

        const maxCount = Math.max(...Object.values(strideCounts), 1);
        const barStartX = leftMargin + 50;
        const barMaxWidth = contentWidth - 60;
        const barHeight = 7;
        const barGap = 3;

        checkPageBreak(strideCategories.length * (barHeight + barGap) + 10);

        strideCategories.forEach((cat, i) => {
            const count = strideCounts[cat.key];
            const barWidth = maxCount > 0 ? (count / maxCount) * barMaxWidth : 0;
            const rowY = yPos + i * (barHeight + barGap);

            // Category label
            doc.setFontSize(8);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(60, 60, 60);
            doc.text(cat.key, leftMargin, rowY + barHeight / 2 + 1);

            // Bar background
            doc.setFillColor(235, 235, 235);
            doc.roundedRect(barStartX, rowY, barMaxWidth, barHeight, 1, 1, 'F');

            // Bar fill
            if (barWidth > 0) {
                doc.setFillColor(...cat.color);
                doc.roundedRect(barStartX, rowY, Math.max(barWidth, 4), barHeight, 1, 1, 'F');
            }

            // Count label
            doc.setFontSize(8);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(...cat.color);
            doc.text(String(count), barStartX + barMaxWidth + 4, rowY + barHeight / 2 + 1);
        });

        yPos += strideCategories.length * (barHeight + barGap) + 8;

        // =============================================
        // INFERRED ARCHITECTURE
        // =============================================
        addHeading("4. Inferred Architecture");

        // Strategy: Re-render using mermaid.render() with htmlLabels:false
        // (generates native SVG <text>, no <foreignObject> that browsers block).
        // Then SVG blob → Image → Canvas → PDF. No html2canvas needed.
        let diagramCaptured = false;

        if (data.diagram) {
            try {
                // Initialize mermaid with htmlLabels OFF to avoid foreignObject
                mermaid.initialize({
                    startOnLoad: false,
                    theme: 'default',
                    securityLevel: 'loose',
                    fontFamily: 'Arial, sans-serif',
                    flowchart: { useMaxWidth: false, htmlLabels: false, curve: 'basis' },
                });

                // Render the diagram fresh
                const diagramId = `pdf-mermaid-${Date.now()}`;
                const { svg: svgString } = await mermaid.render(diagramId, data.diagram);

                // Parse SVG and set explicit large dimensions
                const parser = new DOMParser();
                const svgDoc = parser.parseFromString(svgString, 'image/svg+xml');
                const svgEl = svgDoc.querySelector('svg');

                if (svgEl) {
                    // Get viewBox for aspect ratio
                    const vb = svgEl.getAttribute('viewBox');
                    let vbW = 800, vbH = 600;
                    if (vb) {
                        const parts = vb.split(/[\s,]+/).map(Number);
                        vbW = parts[2] || 800;
                        vbH = parts[3] || 600;
                    }

                    // Set large explicit pixel dimensions for sharp rendering
                    const renderW = 1400;
                    const renderH = Math.round(renderW * (vbH / vbW));
                    svgEl.setAttribute('width', renderW);
                    svgEl.setAttribute('height', renderH);
                    svgEl.setAttribute('xmlns', 'http://www.w3.org/2000/svg');

                    // Add white background rect
                    const bgRect = svgDoc.createElementNS('http://www.w3.org/2000/svg', 'rect');
                    bgRect.setAttribute('width', '100%');
                    bgRect.setAttribute('height', '100%');
                    bgRect.setAttribute('fill', '#ffffff');
                    svgEl.insertBefore(bgRect, svgEl.firstChild);

                    // Serialize to base64 data URI (avoids tainted canvas from blob URL)
                    const serializer = new XMLSerializer();
                    const svgStr = serializer.serializeToString(svgEl);
                    const dataUri = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgStr)));

                    // Load as Image
                    const img = new Image();
                    const loaded = await new Promise(resolve => {
                        img.onload = () => resolve(true);
                        img.onerror = (e) => { console.error('SVG Image load error:', e); resolve(false); };
                        img.src = dataUri;
                    });

                    if (loaded && img.naturalWidth > 0) {
                        // Draw to canvas
                        const canvas = document.createElement('canvas');
                        canvas.width = renderW;
                        canvas.height = renderH;
                        const ctx = canvas.getContext('2d');
                        ctx.fillStyle = '#ffffff';
                        ctx.fillRect(0, 0, renderW, renderH);
                        ctx.drawImage(img, 0, 0, renderW, renderH);

                        const imgData = canvas.toDataURL('image/png');

                        // Place diagram on a DEDICATED new page for maximum visibility
                        doc.addPage();
                        yPos = 15;
                        doc.setFontSize(12);
                        doc.setFont('helvetica', 'bold');
                        doc.setTextColor(44, 62, 80);
                        doc.text("Inferred Architecture Diagram", leftMargin, yPos);
                        yPos += 8;

                        // Calculate size: fill as much of the page as possible
                        const diagramAR = renderH / renderW;
                        const maxW = contentWidth;
                        const maxH = pageHeight - yPos - 20;
                        let pdfW = maxW;
                        let pdfH = pdfW * diagramAR;
                        if (pdfH > maxH) {
                            pdfH = maxH;
                            pdfW = pdfH / diagramAR;
                        }
                        // Enforce minimum height of 80mm
                        if (pdfH < 80) {
                            pdfH = 80;
                        }
                        const xOff = leftMargin + (contentWidth - pdfW) / 2;

                        doc.addImage(imgData, 'PNG', xOff, yPos, pdfW, pdfH);
                        yPos += pdfH + 8;
                        diagramCaptured = true;
                    }
                }
            } catch (e) {
                console.error('Diagram PDF capture failed:', e);
            }
        }

        // Re-initialize mermaid back to default for dashboard rendering
        if (data.diagram) {
            mermaid.initialize({
                startOnLoad: false,
                theme: document.documentElement.classList.contains('dark') ? 'dark' : 'default',
                securityLevel: 'loose',
                fontFamily: 'Arial, sans-serif',
            });
        }

        // Fallback: render the Mermaid code as a styled code block
        if (!diagramCaptured && data.diagram) {
            addText("Architecture Diagram (Mermaid Code):", 9, 'bold', [44, 62, 80]);
            yPos += 2;
            const codeLines = data.diagram.split('\n').slice(0, 35);
            const lineH = 3.2;
            const codeBlockHeight = codeLines.length * lineH + 10;
            checkPageBreak(codeBlockHeight + 5);
            doc.setFillColor(248, 249, 250);
            doc.roundedRect(leftMargin, yPos - 2, contentWidth, codeBlockHeight, 2, 2, 'F');
            doc.setDrawColor(220, 220, 220);
            doc.roundedRect(leftMargin, yPos - 2, contentWidth, codeBlockHeight, 2, 2, 'S');
            doc.setFontSize(5.5);
            doc.setFont('courier', 'normal');
            doc.setTextColor(40, 40, 40);
            codeLines.forEach((line, i) => {
                doc.text(line.substring(0, 110), leftMargin + 3, yPos + 4 + i * lineH);
            });
            const totalLines = data.diagram.split('\n').length;
            if (totalLines > 35) {
                doc.setTextColor(120, 120, 120);
                doc.setFont('courier', 'italic');
                doc.text(`... ${totalLines - 35} more lines`, leftMargin + 3, yPos + 4 + 35 * lineH);
            }
            yPos += codeBlockHeight + 4;
            addText("Tip: Paste this code at mermaid.live to view the interactive diagram.", 7, 'italic', [100, 100, 100]);
        } else if (!diagramCaptured) {
            addText("(Architecture diagram not available)", 8, 'italic', [128, 128, 128]);
        }

        // Build a name lookup from architecture components
        const nameMap = {};
        (data.architecture?.components || []).forEach(c => {
            nameMap[c.id] = c.name || c.id;
        });
        const resolveName = (id) => nameMap[id] || id.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());

        // Components table
        if (data.architecture?.components?.length) {
            yPos += 2;
            addText("Components:", 10, 'bold');

            const compTableX = leftMargin;
            const colWidths = [contentWidth * 0.45, contentWidth * 0.25, contentWidth * 0.30];
            const rowH = 6;

            // Table header
            checkPageBreak(10);
            doc.setFillColor(44, 62, 80);
            doc.rect(compTableX, yPos - 3, contentWidth, rowH + 1, 'F');
            doc.setFontSize(8);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(255, 255, 255);
            doc.text('Component', compTableX + 2, yPos + 1);
            doc.text('Type', compTableX + colWidths[0] + 2, yPos + 1);
            doc.text('Properties', compTableX + colWidths[0] + colWidths[1] + 2, yPos + 1);
            yPos += rowH + 2;

            data.architecture.components.forEach((c, i) => {
                checkPageBreak(rowH + 2);
                if (i % 2 === 0) {
                    doc.setFillColor(245, 245, 245);
                    doc.rect(compTableX, yPos - 3, contentWidth, rowH, 'F');
                }
                doc.setFontSize(8);
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(30, 30, 30);
                doc.text((c.name || c.id).substring(0, 35), compTableX + 2, yPos + 1);
                doc.text((c.type || '—').substring(0, 18), compTableX + colWidths[0] + 2, yPos + 1);
                const props = Object.entries(c.properties || {}).filter(([, v]) => v === true).map(([k]) => k).join(', ');
                doc.text((props || '—').substring(0, 28), compTableX + colWidths[0] + colWidths[1] + 2, yPos + 1);
                yPos += rowH;
            });
            yPos += 4;
        }

        // Data Flows table
        if (data.architecture?.flows?.length) {
            yPos += 2;
            addText("Data Flows:", 10, 'bold');

            const flowTableX = leftMargin;
            const fColWidths = [contentWidth * 0.30, contentWidth * 0.30, contentWidth * 0.20, contentWidth * 0.20];
            const fRowH = 6;

            // Table header
            checkPageBreak(10);
            doc.setFillColor(44, 62, 80);
            doc.rect(flowTableX, yPos - 3, contentWidth, fRowH + 1, 'F');
            doc.setFontSize(8);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(255, 255, 255);
            doc.text('Source', flowTableX + 2, yPos + 1);
            doc.text('Target', flowTableX + fColWidths[0] + 2, yPos + 1);
            doc.text('Protocol', flowTableX + fColWidths[0] + fColWidths[1] + 2, yPos + 1);
            doc.text('Description', flowTableX + fColWidths[0] + fColWidths[1] + fColWidths[2] + 2, yPos + 1);
            yPos += fRowH + 2;

            data.architecture.flows.forEach((f, i) => {
                checkPageBreak(fRowH + 2);
                if (i % 2 === 0) {
                    doc.setFillColor(245, 245, 245);
                    doc.rect(flowTableX, yPos - 3, contentWidth, fRowH, 'F');
                }
                doc.setFontSize(7.5);
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(30, 30, 30);
                doc.text(resolveName(f.source_id).substring(0, 24), flowTableX + 2, yPos + 1);
                doc.text(resolveName(f.target_id).substring(0, 24), flowTableX + fColWidths[0] + 2, yPos + 1);
                doc.text((f.protocol || '—').substring(0, 14).toUpperCase(), flowTableX + fColWidths[0] + fColWidths[1] + 2, yPos + 1);
                doc.text((f.description || '—').substring(0, 18), flowTableX + fColWidths[0] + fColWidths[1] + fColWidths[2] + 2, yPos + 1);
                yPos += fRowH;
            });
            yPos += 4;
        }

        // =============================================
        // CONFIRMED RISKS
        // =============================================
        addHeading("5. Confirmed Risks", 14, [39, 174, 96]);

        if (confirmed.length === 0) {
            addText("No confirmed risks detected.", 10, 'italic', [100, 100, 100]);
        } else {
            confirmed.forEach(t => renderThreat(doc, t, leftMargin, contentWidth, checkPageBreak, () => yPos, (v) => yPos = v));
        }

        // =============================================
        // POTENTIAL RISKS
        // =============================================
        addHeading("6. Potential Risks (Assumption-Based)", 14, [241, 196, 15]);

        if (potential.length === 0) {
            addText("No potential risks detected.", 10, 'italic', [100, 100, 100]);
        } else {
            potential.forEach(t => renderThreat(doc, t, leftMargin, contentWidth, checkPageBreak, () => yPos, (v) => yPos = v));
        }

        // =============================================
        // FOOTER on every page
        // =============================================
        const pageCount = doc.internal.getNumberOfPages();
        for (let i = 1; i <= pageCount; i++) {
            doc.setPage(i);
            // Footer line
            doc.setDrawColor(200, 200, 200);
            doc.line(leftMargin, pageHeight - 15, pageWidth - rightMargin, pageHeight - 15);
            // Footer text
            doc.setFontSize(7);
            doc.setTextColor(150, 150, 150);
            doc.setFont('helvetica', 'normal');
            doc.text(`Page ${i} of ${pageCount}`, pageWidth - 30, pageHeight - 10);
            doc.text(`AI Threat Modeler • ${projectName || 'Report'}`, leftMargin, pageHeight - 10);
            doc.text(new Date().toLocaleDateString(), pageWidth / 2, pageHeight - 10, { align: 'center' });
        }

        doc.save(`${(projectName || 'Threat_Report').replace(/\s+/g, '_')}.pdf`);

        // =============================================
        // RENDER INDIVIDUAL THREAT
        // =============================================
        function renderThreat(doc, t, leftMargin, contentWidth, checkPageBreak, getY, setY) {
            let y = getY();
            checkPageBreak(55);
            y = getY();

            // Severity color
            const sevColors = { Critical: [231, 76, 60], High: [230, 126, 34], Medium: [241, 196, 15], Low: [52, 152, 219] };
            const sevColor = sevColors[t.severity] || [100, 100, 100];

            // Header bar
            doc.setFillColor(...sevColor);
            doc.roundedRect(leftMargin, y - 4, contentWidth, 8, 1, 1, 'F');
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(9);
            doc.setFont('helvetica', 'bold');
            doc.text(`[${t.severity}] ${t.title}`.substring(0, 85), leftMargin + 3, y + 1);
            y += 10;
            setY(y);

            // Meta line
            doc.setTextColor(100, 100, 100);
            doc.setFontSize(7);
            doc.setFont('helvetica', 'normal');
            const metaParts = [t.category, `Confidence: ${t.confidence}`];
            if (t.stride_category && t.stride_category !== t.category) metaParts.push(`STRIDE: ${t.stride_category}`);
            doc.text(metaParts.join(' | '), leftMargin, y);
            y += 5;
            setY(y);

            // Description
            doc.setTextColor(50, 50, 50);
            doc.setFontSize(9);
            const descLines = doc.splitTextToSize(t.description || '', contentWidth - 5);
            doc.text(descLines.slice(0, 4), leftMargin, y);
            y += descLines.slice(0, 4).length * 4 + 2;
            setY(y);
            checkPageBreak(20);
            y = getY();

            // Affected components
            if (t.affected_components?.length) {
                doc.setFontSize(7);
                doc.setFont('helvetica', 'bold');
                doc.setTextColor(80, 80, 80);
                doc.text("Affected: ", leftMargin, y);
                doc.setFont('helvetica', 'normal');
                doc.text(t.affected_components.join(', ').substring(0, 80), leftMargin + 16, y);
                y += 4;
                setY(y);
            }

            // Evidence
            if (t.evidence?.length) {
                doc.setFontSize(7);
                doc.setFont('helvetica', 'italic');
                doc.setTextColor(100, 100, 100);
                doc.text(`Evidence: ${t.evidence.slice(0, 2).join('; ').substring(0, 90)}`, leftMargin, y);
                y += 4;
                setY(y);
            }

            // Compliance/Framework Mappings
            const complianceParts = [];
            if (t.cwe?.length) complianceParts.push(`CWE: ${t.cwe.join(', ')}`);
            if (t.mitre_attack?.length) complianceParts.push(`MITRE: ${t.mitre_attack.join(', ')}`);
            if (t.owasp_top_10?.length) complianceParts.push(`OWASP: ${t.owasp_top_10.map(o => o.split('-')[0]).join(', ')}`);
            if (t.nist_800_53?.length) complianceParts.push(`NIST: ${t.nist_800_53.join(', ')}`);

            if (complianceParts.length > 0) {
                doc.setFontSize(6.5);
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(80, 80, 140);
                doc.text(complianceParts.join('  |  ').substring(0, 120), leftMargin, y);
                y += 4;
                setY(y);
            }

            // Mitigation box
            doc.setFillColor(232, 245, 233);
            const mitText = t.mitigation || 'N/A';
            const mitLines = doc.splitTextToSize(mitText, contentWidth - 28);
            const mitBoxHeight = Math.max(mitLines.slice(0, 3).length * 4 + 4, 10);

            checkPageBreak(mitBoxHeight + 5);
            y = getY();

            doc.roundedRect(leftMargin, y - 2, contentWidth, mitBoxHeight, 1, 1, 'F');
            doc.setFontSize(7);
            doc.setFont('helvetica', 'bold');
            doc.setTextColor(39, 174, 96);
            doc.text("✓ Mitigation:", leftMargin + 2, y + 3);
            doc.setFont('helvetica', 'normal');
            doc.setTextColor(30, 30, 30);
            doc.text(mitLines.slice(0, 3), leftMargin + 24, y + 3);

            y += mitBoxHeight + 6;
            setY(y);
        }

    } catch (error) {
        console.error("PDF Generation Error:", error);
        alert(`PDF generation failed: ${error.message}`);
    }
};
