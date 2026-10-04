// 日志中心 —— 与队列页共用表格与详情面板，Tab 停留在「日志」
import MailQueue from "./MailQueue";

export default function Logs() {
  return <MailQueue initialTab="logs" />;
}
