package burp.Logs;

import burp.Filter.Filters;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

public class LogTableModel extends AbstractTableModel {

  private final ArrayList<LogEntry> log;
  private ArrayList<LogEntry> filteredLogs;

  public LogTableModel() {
    log = new ArrayList<>();
    filteredLogs = new ArrayList<>();
  }

  public void addLogEntry(LogEntry logEntry, Filters filters) {
    log.add(logEntry);
    if(filters.filter(logEntry)) {
      filteredLogs.add(logEntry);
    }
    fireTableDataChanged();
  }

  public void filterLogs(Filters filters) {
    filteredLogs = new ArrayList<>();
    for (LogEntry logEntry : log) {
      if(filters.filter(logEntry)) {
        filteredLogs.add(logEntry);
        //System.out.println("Adding row "+logEntry.getRequestResponseId());
        fireTableDataChanged();
      }
    }
    fireTableDataChanged();
    //new Thread(() -> {
    //}).start();
  }

  public void clearLogs() {
    log.clear();
    filteredLogs.clear();
    fireTableDataChanged();
  }

  public LogEntry getLogEntry(int row) {
    //return log.get(row);
    return filteredLogs.get(row);
  }

  public ArrayList<LogEntry> getLog() {
    //return log;
    return log;
  }

  public ArrayList<LogEntry> getFilteredLogs() {
    //return log;
    return filteredLogs;
  }

  public int getLogCount() {
    return log.size();
  }

  @Override
  public int getRowCount() {
    //return log.size();
    return filteredLogs.size();
  }

  @Override
  public int getColumnCount() {
    return 11;
  }

  @Override
  public String getColumnName(int columnIndex) {
    switch (columnIndex) {
      case 0:
        return "#";
      case 1:
        return "Method";
      case 2:
        return "URL";
      case 3:
        return "Orig. Status";
      case 4:
        return "Status";
      case 5:
        return "Orig. Resp. Len.";
      case 6:
        return "Resp. Len.";
      case 7:
        return "Resp. Len. Diff.";
      case 8:
        return "Orig. Res. Time";
      case 9:
        return "Mod. Res. Time";
      case 10:
        return "Time diff";
      default:
        return "";
    }
  }

  @Override
  public Class<?> getColumnClass(int columnIndex) {
    switch (columnIndex) {
      case 0:
        return Integer.class;
      case 1:
        return String.class;
      case 2:
        return String.class;
      case 3:
        return Integer.class;
      case 4:
        return Integer.class;
      case 5:
        return Integer.class;
      case 6:
        return Integer.class;
      case 7:
        return Integer.class;
      case 8:
        return String.class;
      case 9:
        return String.class;
      case 10:
        return long.class;
      default:
        return null;
    }
  }

  @Override
  public Object getValueAt(int rowIndex, int columnIndex) {
    //LogEntry logEntry = log.get(rowIndex);
    LogEntry logEntry = filteredLogs.get(rowIndex);
    // ID, Mod Method, Mod URL, Orig Status, Mod Status, Orig Size, Mod Size, Size Difference, Response Distance
    switch (columnIndex) {
      case 0:
        return logEntry.getRequestResponseId();
      case 1:
        return logEntry.getModifiedMethod();
      case 2:
        return logEntry.getModifiedURL().toString();
      case 3:
        return logEntry.getOriginalResponseStatus();
      case 4:
        return logEntry.getModifiedResponseStatus();
      case 5:
        return logEntry.getOriginalLength();
      case 6:
        return logEntry.getModifiedLength();
      case 7:
        return logEntry.getLengthDifference();
      case 8:
        return logEntry.getOriginalDateHeaderValue();
      case 9:
        return logEntry.getModifiedDateHeaderValue();
      case 10:
        return logEntry.getTimeDifference();
      default:
        return "";
    }
  }
}
