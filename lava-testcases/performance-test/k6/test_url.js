import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: parseInt(__ENV.VUS || "50"),
  duration: __ENV.DURATION || "60s",
};

export default function () {
  const targetUrl = __ENV.TARGET_URL;
  if (!targetUrl) throw new Error("缺少TARGET_URL");

  const reqOpt = {
    timeout: "30s",
    headers: {
      "Connection": "close" // 每次请求主动断开连接，不复用长连接
    }
  };
  const res = http.get(targetUrl, reqOpt);

  check(res, { "200 ok": r => r.status === 200 });
  sleep(0.5);
}