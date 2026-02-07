package com.rauulssanchezz.adminauthmailjettemplate.admindashboard;

public record AdminDashboardItemDto(String name, long count, String icon, String link) implements AdminDashboardItemInterface {
    @Override public String getDisplayName() { return name; }
    @Override public long getCount() { return count; }
    @Override public String getIcon() { return icon; }
    @Override public String getLink() { return link; }
}
