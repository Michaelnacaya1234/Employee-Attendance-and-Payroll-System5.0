/**
 * ATTENDANCE DEDUCTIONS MANAGEMENT MODULE
 * Comprehensive system for calculating and managing payroll deductions
 * Handles late arrivals, undertime, absences, and overtime calculations
 */
class AttendanceDeductions {
  constructor() {
    this.apiUrl = 'api/attendance-deductions.php';
    this.settings = {};
    this.init();
  }

  /**
   * INITIALIZE DEDUCTIONS SYSTEM
   * Loads system settings and prepares calculation environment
   */
  async init() {
    await this.loadSystemSettings();
  }

  /**
   * LOAD SYSTEM DEDUCTION SETTINGS
   * Retrieves configuration for work hours, grace periods, and rates
   * Provides fallback defaults if API call fails
   */
  async loadSystemSettings() {
    try {
      const response = await fetch(`${this.apiUrl}?operation=getSystemSettings`);
      const data = await response.json();
      this.settings = data;
    } catch (error) {
      console.error('Error loading system settings:', error);
      // Set default values
      this.settings = {
        work_hours_per_day: 12,
        lunch_hours_per_day: 1,
        grace_period_minutes: 0,
        rounding_interval_minutes: 0,
        overtime_multiplier: 1.25,
        late_deduction_enabled: 1,
        undertime_deduction_enabled: 1,
        absent_deduction_enabled: 1,
        paid_hours_per_day: 12,
        use_exact_minutes_for_late: 1,
      };
    }
  }

  /**
   * UPDATE SYSTEM DEDUCTION SETTINGS
   * Saves new configuration values to database
   * Returns success/failure status with error handling
   */
  async updateSystemSettings(settings) {
    try {
      const response = await fetch(this.apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `operation=updateSystemSettings&json=${encodeURIComponent(JSON.stringify(settings))}`
      });
      const data = await response.json();
      if (data.success) {
        await this.loadSystemSettings();
      }
      return data;
    } catch (error) {
      console.error('Error updating system settings:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * CALCULATE ATTENDANCE DEDUCTIONS
   * Computes late, absent, and undertime deductions for date range
   * Returns detailed breakdown with amounts and formulas
   */
  async calculateDeductions(employeeId, startDate, endDate) {
    try {
      const response = await fetch(this.apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `operation=calculateDeductions&json=${encodeURIComponent(JSON.stringify({
          employee_id: employeeId,
          start_date: startDate,
          end_date: endDate
        }))}`
      });
      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Error calculating deductions:', error);
      return { error: error.message };
    }
  }

  /**
   * CALCULATE PAYROLL PERIOD DEDUCTIONS
   * Processes complete payroll cycle deductions
   * Includes overtime pay and comprehensive totals
   */
  async calculatePayrollDeductions(employeeId, startDate, endDate) {
    try {
      const response = await fetch(this.apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `operation=calculatePayrollDeductions&json=${encodeURIComponent(JSON.stringify({
          employee_id: employeeId,
          start_date: startDate,
          end_date: endDate
        }))}`
      });
      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Error calculating payroll deductions:', error);
      return { error: error.message };
    }
  }

  /**
   * MANUAL DEDUCTION CALCULATION ENGINE
   * Implements core deduction formulas without API dependency
   * Provides detailed breakdown with hourly rates and per-minute calculations
   */
  calculateDeductionsManually(dailyWage, workHours, lunchHours, lateMinutes, undertimeMinutes, absentMinutes, overtimeMinutes) {
    const paidHours = workHours - lunchHours;
    const hourlyRate = dailyWage / paidHours;
    const perMinuteRate = hourlyRate / 60;
    
    // Late deduction
    const lateDeduction = (dailyWage / paidHours / 60) * lateMinutes;
    
    // Undertime deduction
    const undertimeDeduction = (dailyWage / paidHours / 60) * undertimeMinutes;
    
    // Absent deduction
    const absentDeduction = (dailyWage / paidHours / 60) * (absentMinutes * 60);
    
    // Overtime pay
    const overtimePay = (dailyWage / paidHours / 60) * overtimeMinutes * this.settings.overtime_multiplier;
    
    const netPay = dailyWage - lateDeduction - undertimeDeduction - absentDeduction + overtimePay;
    
    return {
      daily_wage: dailyWage,
      hourly_rate: hourlyRate,
      per_minute_rate: perMinuteRate,
      late_deduction: lateDeduction,
      undertime_deduction: undertimeDeduction,
      absent_deduction: absentDeduction,
      overtime_pay: overtimePay,
      net_pay: netPay,
      formulas: {
        late_formula: `Net = ${dailyWage} - (${dailyWage} / ${paidHours} / 60) × ${lateMinutes} = ${netPay.toFixed(2)}`,
        undertime_formula: `Net = ${dailyWage} - (${dailyWage} / ${paidHours} / 60) × ${undertimeMinutes} = ${netPay.toFixed(2)}`,
        overtime_formula: `Net = ${dailyWage} + (${dailyWage} / ${paidHours} / 60) × ${overtimeMinutes} × ${this.settings.overtime_multiplier} = ${netPay.toFixed(2)}`,
        absent_formula: `Net = ${dailyWage} - (${dailyWage} / ${paidHours} / 60) × ${absentMinutes * 60} = ${netPay.toFixed(2)}`
      }
    };
  }

  /**
   * FORMAT TIME FOR DISPLAY
   * Converts 24-hour time strings to readable 12-hour format
   * Handles null/empty values gracefully
   */
  formatTime(timeString) {
    if (!timeString) return 'N/A';
    const time = new Date(`2000-01-01T${timeString}`);
    return time.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit',
      hour12: true 
    });
  }

  /**
   * FORMAT CURRENCY VALUES
   * Displays monetary amounts in Philippine Peso format
   * Ensures consistent currency presentation
   */
  formatCurrency(amount) {
    return new Intl.NumberFormat('en-PH', {
      style: 'currency',
      currency: 'PHP'
    }).format(amount);
  }

  /**
   * CREATE DEDUCTIONS SUMMARY TABLE
   * Generates comprehensive HTML table with breakdown details
   * Includes work days, absent days, and wage calculations
   */
  createDeductionsTable(data, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const { summary, daily_breakdown, formulas_used } = data;
    
    let html = `
      <div class="bg-white rounded-lg shadow-md p-6 mb-6">
        <h3 class="text-lg font-semibold text-gray-800 mb-4">Deductions Summary</h3>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div class="text-center">
            <div class="text-2xl font-bold text-blue-600">${summary.total_work_days}</div>
            <div class="text-sm text-gray-600">Work Days</div>
          </div>
          <div class="text-center">
            <div class="text-2xl font-bold text-red-600">${summary.total_absent_days}</div>
            <div class="text-sm text-gray-600">Absent Days</div>
          </div>
          <div class="text-center">
            <div class="text-2xl font-bold text-green-600">${this.formatCurrency(summary.daily_wage)}</div>
            <div class="text-sm text-gray-600">Daily Wage</div>
          </div>
          <div class="text-center">
            <div class="text-2xl font-bold text-purple-600">${this.formatCurrency(summary.net_pay)}</div>
            <div class="text-sm text-gray-600">Net Pay</div>
          </div>
        </div>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 class="font-semibold text-gray-700 mb-3">Deductions</h4>
            <div class="space-y-2">
              <div class="flex justify-between">
                <span class="text-gray-600">Late Deduction:</span>
                <span class="font-medium text-red-600">-${this.formatCurrency(summary.total_late_deduction)}</span>
              </div>
              <div class="flex justify-between">
                <span class="text-gray-600">Undertime Deduction:</span>
                <span class="font-medium text-red-600">-${this.formatCurrency(summary.total_undertime_deduction)}</span>
              </div>
              <div class="flex justify-between">
                <span class="text-gray-600">Absent Deduction:</span>
                <span class="font-medium text-red-600">-${this.formatCurrency(summary.total_absent_deduction)}</span>
              </div>
              <div class="border-t pt-2">
                <div class="flex justify-between font-semibold">
                  <span>Total Deductions:</span>
                  <span class="text-red-600">-${this.formatCurrency(summary.total_deductions)}</span>
                </div>
              </div>
            </div>
          </div>
          
          <div>
            <h4 class="font-semibold text-gray-700 mb-3">Earnings</h4>
            <div class="space-y-2">
              <div class="flex justify-between">
                <span class="text-gray-600">Basic Pay:</span>
                <span class="font-medium text-green-600">${this.formatCurrency(summary.gross_pay - summary.total_overtime_pay)}</span>
              </div>
              <div class="flex justify-between">
                <span class="text-gray-600">Overtime Pay:</span>
                <span class="font-medium text-green-600">+${this.formatCurrency(summary.total_overtime_pay)}</span>
              </div>
              <div class="border-t pt-2">
                <div class="flex justify-between font-semibold">
                  <span>Gross Pay:</span>
                  <span class="text-green-600">${this.formatCurrency(summary.gross_pay)}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Add formulas section
    html += `
      <div class="bg-white rounded-lg shadow-md p-6 mb-6">
        <h3 class="text-lg font-semibold text-gray-800 mb-4">Formulas Used</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h4 class="font-medium text-gray-700 mb-2">Rates</h4>
            <div class="text-sm text-gray-600 space-y-1">
              <div>Hourly Rate: ${this.formatCurrency(formulas_used.hourly_rate)}/hr</div>
              <div>Per-Minute Rate: ${this.formatCurrency(formulas_used.per_minute_rate)}/min</div>
              <div>Paid Hours/Day: ${formulas_used.paid_hours_per_day} hrs</div>
              <div>OT Multiplier: ${formulas_used.overtime_multiplier}x</div>
            </div>
          </div>
          <div>
            <h4 class="font-medium text-gray-700 mb-2">Quick Formulas</h4>
            <div class="text-sm text-gray-600 space-y-1">
              <div><strong>Late:</strong> Net = DailyWage - (DailyWage / PaidHours / 60) × LateMinutes</div>
              <div><strong>Undertime:</strong> Net = DailyWage - (DailyWage / PaidHours / 60) × UndertimeMinutes</div>
              <div><strong>Overtime:</strong> Net = DailyWage + (DailyWage / PaidHours / 60) × OTMinutes × OTMultiplier</div>
              <div><strong>Absent:</strong> Net = DailyWage - (DailyWage / PaidHours / 60) × AbsentMinutes</div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Add daily breakdown table
    if (daily_breakdown && daily_breakdown.length > 0) {
      html += `
        <div class="bg-white rounded-lg shadow-md p-6">
          <h3 class="text-lg font-semibold text-gray-800 mb-4">Daily Breakdown</h3>
          <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
              <thead class="bg-gray-50">
                <tr>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Daily Wage</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Late Deduction</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Undertime Deduction</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Overtime Pay</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Daily Net</th>
                </tr>
              </thead>
              <tbody class="bg-white divide-y divide-gray-200">
      `;

      daily_breakdown.forEach(day => {
        html += `
          <tr>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${day.date}</td>
            <td class="px-6 py-4 whitespace-nowrap">
              <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                day.status === 'present' ? 'bg-green-100 text-green-800' : 
                day.status === 'absent' ? 'bg-red-100 text-red-800' : 
                'bg-yellow-100 text-yellow-800'
              }">${day.status}</span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${this.formatCurrency(day.daily_wage)}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-red-600">${day.late_deduction > 0 ? '-' + this.formatCurrency(day.late_deduction) : '-'}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-red-600">${day.undertime_deduction > 0 ? '-' + this.formatCurrency(day.undertime_deduction) : '-'}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-green-600">${day.overtime_pay > 0 ? '+' + this.formatCurrency(day.overtime_pay) : '-'}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${this.formatCurrency(day.daily_net)}</td>
          </tr>
        `;
      });

      html += `
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    container.innerHTML = html;
  }

  /**
   * Create a settings form for deduction configuration
   */
  createSettingsForm(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const html = `
      <div class="bg-white rounded-lg shadow-md p-6">
        <h3 class="text-lg font-semibold text-gray-800 mb-4">Deduction Settings</h3>
        <form id="deductionSettingsForm" class="space-y-4">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label class="block text-sm font-medium text-gray-700">Work Hours per Day</label>
              <input type="number" step="0.5" min="1" max="24" 
                     value="${this.settings.work_hours_per_day || 12}"
                     name="work_hours_per_day"
                     class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700">Lunch Hours per Day</label>
              <input type="number" step="0.5" min="0" max="8" 
                     value="${this.settings.lunch_hours_per_day || 1}"
                     name="lunch_hours_per_day"
                     class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700">Grace Period (minutes)</label>
              <input type="number" step="5" min="0" max="60" 
                     value="${this.settings.grace_period_minutes || 15}"
                     name="grace_period_minutes"
                     class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700">Rounding Interval (minutes)</label>
              <input type="number" step="5" min="0" max="60" 
                     value="${this.settings.rounding_interval_minutes || 15}"
                     name="rounding_interval_minutes"
                     class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700">Overtime Multiplier</label>
              <input type="number" step="0.05" min="1" max="3" 
                     value="${this.settings.overtime_multiplier || 1.25}"
                     name="overtime_multiplier"
                     class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700">Paid Hours per Day</label>
              <input type="number" step="0.5" min="1" max="24"
                     value="${this.settings.paid_hours_per_day || 12}"
                     name="paid_hours_per_day"
                     class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
            </div>
          </div>
          
          <div class="space-y-3">
            <h4 class="font-medium text-gray-700">Enable Deductions</h4>
            <div class="flex items-center space-x-6">
              <label class="flex items-center">
                <input type="checkbox" 
                       ${this.settings.late_deduction_enabled ? 'checked' : ''}
                       name="late_deduction_enabled"
                       class="rounded border-gray-300 text-blue-600 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                <span class="ml-2 text-sm text-gray-700">Late Deductions</span>
              </label>
              <label class="flex items-center">
                <input type="checkbox" 
                       ${this.settings.undertime_deduction_enabled ? 'checked' : ''}
                       name="undertime_deduction_enabled"
                       class="rounded border-gray-300 text-blue-600 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                <span class="ml-2 text-sm text-gray-700">Undertime Deductions</span>
              </label>
              <label class="flex items-center">
                <input type="checkbox" 
                       ${this.settings.absent_deduction_enabled ? 'checked' : ''}
                       name="absent_deduction_enabled"
                       class="rounded border-gray-300 text-blue-600 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                <span class="ml-2 text-sm text-gray-700">Absent Deductions</span>
              </label>
              <label class="flex items-center">
                <input type="checkbox" 
                       ${this.settings.use_exact_minutes_for_late ? 'checked' : ''}
                       name="use_exact_minutes_for_late"
                       class="rounded border-gray-300 text-blue-600 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                <span class="ml-2 text-sm text-gray-700">Exact Late Minutes (no rounding/grace)</span>
              </label>
            </div>
          </div>
          
          <div class="flex justify-end">
            <button type="submit" 
                    class="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
              Save Settings
            </button>
          </div>
        </form>
      </div>
    `;

    container.innerHTML = html;
    this.bindSettingsForm();
  }

  /**
   * Bind events to the settings form
   */
  bindSettingsForm() {
    const form = document.getElementById('deductionSettingsForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();

      const settings = {};
      // Ensure we capture unchecked checkboxes as 0
      form.querySelectorAll('input[name]').forEach(input => {
        const key = input.name;
        if (input.type === 'checkbox') {
          settings[key] = input.checked ? 1 : 0;
        } else {
          const num = parseFloat(input.value);
          settings[key] = Number.isFinite(num) ? num : 0;
        }
      });

      const result = await this.updateSystemSettings(settings);
      if (result.success) {
        alert('Settings updated successfully!');
      } else {
        alert('Error updating settings: ' + (result.error || 'Unknown error'));
      }
    });
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AttendanceDeductions;
} else {
  window.AttendanceDeductions = AttendanceDeductions;
}
