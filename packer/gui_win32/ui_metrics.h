// CipherShell GUI - 共用布局常量。
//
// 全手写坐标布局（不用对话框资源模板），靠这些常量保证各个标签页里
// 标签列/控件列对齐一致、行距统一。所有标签页内容（含"运行"页）都在同一个
// 标签控件里，窗口固定大小，不做动态重排——这样可以把精力放在"对齐工整"
// 而不是响应式布局上。
#pragma once

namespace CipherShellGui::Metrics {

constexpr int kWindowWidth = 780;
constexpr int kWindowHeight = 760;

constexpr int kTabX = 10;
constexpr int kTabY = 10;
constexpr int kTabWidth = 760;
constexpr int kTabHeight = 730;

// 标签页内容相对主窗口左上角的偏移：顶部要让开标签条本身的高度。
constexpr int kPageOffsetX = 10;
constexpr int kPageOffsetY = 30;
constexpr int kPageMarginLeft = kTabX + kPageOffsetX;
constexpr int kPageMarginTop = kTabY + kPageOffsetY;
constexpr int kPageWidth = kTabWidth - 2 * kPageOffsetX;
constexpr int kPageHeight = kTabHeight - kPageOffsetY - kPageOffsetX;

constexpr int kRowHeight = 23;
constexpr int kLabelHeight = 18;
constexpr int kControlHeight = 21;
constexpr int kLabelWidth = 190;
constexpr int kControlX = kPageMarginLeft + kLabelWidth + 10;
constexpr int kControlWidth = kPageMarginLeft + kPageWidth - kControlX;
constexpr int kShortWidth = 70;
constexpr int kBrowseButtonWidth = 110;
constexpr int kGroupGap = 8;

} // namespace CipherShellGui::Metrics
