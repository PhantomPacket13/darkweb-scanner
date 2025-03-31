/**
 * Chart configuration utilities for the Onion Scanner application
 */

/**
 * Creates a pie chart with the provided context and data
 * 
 * @param {CanvasRenderingContext2D} ctx - The canvas 2D context
 * @param {Object} data - The chart data object
 * @returns {Chart} The created chart instance
 */
function createPieChart(ctx, data) {
    return new Chart(ctx, {
        type: 'pie',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#ffffff'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Creates a bar chart with the provided context and data
 * 
 * @param {CanvasRenderingContext2D} ctx - The canvas 2D context
 * @param {Object} data - The chart data object
 * @param {Object} options - Additional chart options
 * @returns {Chart} The created chart instance
 */
function createBarChart(ctx, data, options = {}) {
    const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true,
                ticks: {
                    color: '#ffffff'
                },
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)'
                }
            },
            x: {
                ticks: {
                    color: '#ffffff'
                },
                grid: {
                    color: 'rgba(255, 255, 255, 0.1)'
                }
            }
        },
        plugins: {
            legend: {
                labels: {
                    color: '#ffffff'
                }
            }
        }
    };
    
    const mergedOptions = {...defaultOptions, ...options};
    
    return new Chart(ctx, {
        type: 'bar',
        data: data,
        options: mergedOptions
    });
}

/**
 * Creates a radar chart for comparing security aspects
 * 
 * @param {CanvasRenderingContext2D} ctx - The canvas 2D context
 * @param {Object} data - The chart data object
 * @returns {Chart} The created chart instance
 */
function createSecurityRadarChart(ctx, data) {
    return new Chart(ctx, {
        type: 'radar',
        data: data,
        options: {
            elements: {
                line: {
                    borderWidth: 3
                }
            },
            scales: {
                r: {
                    angleLines: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    pointLabels: {
                        color: '#ffffff'
                    },
                    ticks: {
                        color: '#ffffff',
                        backdropColor: 'transparent'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#ffffff'
                    }
                }
            }
        }
    });
}
