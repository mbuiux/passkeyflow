(function () {
    function clamp(value, min, max) {
        return Math.min(Math.max(value, min), max);
    }

    function hexToRgb(hex) {
        var clean = String(hex || "").replace("#", "").trim();
        if (!/^[0-9a-f]{6}$/i.test(clean)) {
            return null;
        }

        return {
            r: parseInt(clean.slice(0, 2), 16),
            g: parseInt(clean.slice(2, 4), 16),
            b: parseInt(clean.slice(4, 6), 16)
        };
    }

    function toRgba(hex, alpha) {
        var rgb = hexToRgb(hex);
        if (!rgb) {
            return "rgba(100, 116, 139, " + String(alpha) + ")";
        }

        return "rgba(" + rgb.r + ", " + rgb.g + ", " + rgb.b + ", " + String(clamp(alpha, 0, 1)) + ")";
    }

    function isDarkColor(hex) {
        var rgb = hexToRgb(hex);
        if (!rgb) {
            return false;
        }

        // Perceived luminance (sRGB).
        var luminance = (0.2126 * rgb.r + 0.7152 * rgb.g + 0.0722 * rgb.b) / 255;
        return luminance < 0.53;
    }

    function normalizeProviderLabel(value) {
        return String(value || "")
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, " ")
            .trim();
    }

    function providerColorFromLabel(label) {
        var normalized = normalizeProviderLabel(label);

        if (normalized.indexOf("apple") !== -1 || normalized.indexOf("icloud") !== -1 || normalized.indexOf("safari") !== -1) {
            return "#111827";
        }
        if (normalized.indexOf("google") !== -1 || normalized.indexOf("android") !== -1 || normalized.indexOf("chrome") !== -1) {
            return "#16a34a";
        }
        if (normalized.indexOf("microsoft") !== -1 || normalized.indexOf("windows") !== -1 || normalized.indexOf("edge") !== -1) {
            return "#2563eb";
        }
        if (normalized.indexOf("1password") !== -1) {
            return "#ef4444";
        }
        if (normalized.indexOf("lastpass") !== -1) {
            return "#b91c1c";
        }
        if (normalized.indexOf("dashlane") !== -1) {
            return "#ea580c";
        }
        if (normalized.indexOf("bitwarden") !== -1) {
            return "#0f766e";
        }
        if (normalized.indexOf("keeper") !== -1) {
            return "#9333ea";
        }
        if (normalized.indexOf("yubikey") !== -1 || normalized.indexOf("yubi") !== -1) {
            return "#0ea5e9";
        }
        if (normalized.indexOf("other") !== -1 || normalized.indexOf("unknown") !== -1) {
            return "#64748b";
        }

        // Deterministic fallback for unknown providers to keep colors stable across installs.
        var fallbackPalette = ["#7e5bef", "#16a39f", "#22c55e", "#f97316", "#ef4444", "#0ea5e9", "#9333ea", "#64748b"];
        var hash = 0;
        for (var i = 0; i < normalized.length; i += 1) {
            hash = (hash * 31 + normalized.charCodeAt(i)) >>> 0;
        }

        return fallbackPalette[hash % fallbackPalette.length];
    }

    function parseChartPayload(node, attributeName) {
        if (!node) {
            return null;
        }

        var raw = node.getAttribute(attributeName);
        if (!raw) {
            return null;
        }

        try {
            return JSON.parse(raw);
        } catch (error) {
            return null;
        }
    }

    function buildOptions(payload) {
        var labels = Array.isArray(payload.labels) ? payload.labels : [];
        var successCounts = Array.isArray(payload.success) ? payload.success : [];
        var blockedCounts = Array.isArray(payload.blocked) ? payload.blocked : [];
        var failedCounts = Array.isArray(payload.failed) ? payload.failed : [];

        // Backward compatibility for older payloads.
        if (!successCounts.length && Array.isArray(payload.counts)) {
            successCounts = payload.counts;
        }

        return {
            chart: {
                type: "area",
                height: 126,
                toolbar: {
                    show: false
                },
                zoom: {
                    enabled: false
                },
                animations: {
                    enabled: true,
                    easing: "easeinout",
                    speed: 420
                }
            },
            series: [
                {
                    name: "Successful",
                    data: successCounts
                },
                {
                    name: "Blocked",
                    data: blockedCounts
                },
                {
                    name: "Failed",
                    data: failedCounts
                }
            ],
            colors: ["#15803d", "#d97706", "#dc2626"],
            stroke: {
                curve: "smooth",
                width: [3.4, 3, 3]
            },
            fill: {
                type: "gradient",
                gradient: {
                    shadeIntensity: 0,
                    opacityFrom: 0.3,
                    opacityTo: 0.03,
                    stops: [0, 82, 100]
                }
            },
            dataLabels: {
                enabled: false
            },
            markers: {
                size: 0,
                hover: {
                    sizeOffset: 2
                }
            },
            xaxis: {
                categories: labels,
                labels: {
                    style: {
                        colors: "#6b7280",
                        fontSize: "10px",
                        fontFamily: "inherit"
                    }
                },
                axisBorder: {
                    show: false
                },
                axisTicks: {
                    show: false
                }
            },
            yaxis: {
                min: 0,
                forceNiceScale: true,
                labels: {
                    show: false
                }
            },
            grid: {
                borderColor: "rgba(148, 163, 184, 0.24)",
                strokeDashArray: 3,
                xaxis: {
                    lines: {
                        show: false
                    }
                }
            },
            legend: {
                show: true,
                position: "top",
                horizontalAlign: "left",
                fontSize: "11px",
                fontFamily: "inherit",
                labels: {
                    colors: "#475569"
                }
            },
            tooltip: {
                theme: "light",
                x: {
                    show: true
                }
            }
        };
    }

    function buildAuthDonutOptions(payload) {
        var labels = Array.isArray(payload.labels) ? payload.labels : [];
        var series = Array.isArray(payload.series) ? payload.series : [];
        var colors = labels.map(providerColorFromLabel);

        return {
            chart: {
                type: "donut",
                height: 200,
                toolbar: {
                    show: false
                }
            },
            labels: labels,
            series: series,
            colors: colors,
            stroke: {
                width: 2,
                colors: ["#ffffff"]
            },
            dataLabels: {
                enabled: false
            },
            legend: {
                position: "bottom",
                fontSize: "11px",
                fontFamily: "inherit",
                labels: {
                    colors: "#475569"
                },
                itemMargin: {
                    horizontal: 8,
                    vertical: 2
                }
            },
            plotOptions: {
                pie: {
                    donut: {
                        size: "66%"
                    }
                }
            },
            tooltip: {
                theme: "light"
            }
        };
    }

    function renderActivityCharts() {
        if (typeof window.ApexCharts !== "function") {
            return;
        }

        document.querySelectorAll(".wpkpro-dashboard-activity-chart").forEach(function (node) {
            var payload = parseChartPayload(node, "data-activity-chart");
            if (!payload) {
                return;
            }

            var options = buildOptions(payload);
            var chart = new window.ApexCharts(node, options);
            chart.render();
        });

        document.querySelectorAll(".wpkpro-dashboard-auth-chart").forEach(function (node) {
            var payload = parseChartPayload(node, "data-auth-chart");
            if (!payload) {
                return;
            }

            var options = buildAuthDonutOptions(payload);
            var chart = new window.ApexCharts(node, options);
            chart.render();
        });

        document.querySelectorAll(".wpkpro-dashboard-auth-badge[data-provider]").forEach(function (badge) {
            var provider = badge.getAttribute("data-provider") || "";
            var providerKey = normalizeProviderLabel(provider);
            var isUnknownProvider = providerKey.indexOf("unknown") !== -1 || providerKey.indexOf("other") !== -1;
            var color = providerColorFromLabel(provider);
            var darkColor = isDarkColor(color);
            var textColor = isUnknownProvider ? "#334155" : (darkColor ? "#ffffff" : "#111827");
            var backgroundColor = isUnknownProvider
                ? toRgba(color, 0.18)
                : (darkColor ? color : toRgba(color, 0.2));
            var borderColor = isUnknownProvider
                ? toRgba(color, 0.38)
                : (darkColor ? toRgba(color, 0.92) : toRgba(color, 0.46));

            badge.style.backgroundColor = backgroundColor;
            badge.style.borderColor = borderColor;
            badge.style.color = textColor;
            badge.style.textShadow = darkColor && !isUnknownProvider ? "0 1px 0 rgba(0, 0, 0, 0.18)" : "none";
            badge.style.boxShadow = "inset 0 1px 0 rgba(255,255,255,0.55)";
        });
    }

    document.addEventListener("DOMContentLoaded", renderActivityCharts);
})();
