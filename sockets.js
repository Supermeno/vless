import net from "node:net";

export function connect({ hostname, port }) {
  const socket = net.createConnection({ host: hostname, port: Number(port) });
  let isClosed = false;

  const readable = new ReadableStream({
    start(controller) {
      socket.on("data", (chunk) => {
        controller.enqueue(new Uint8Array(chunk));
      });
      socket.on("end", () => {
        if (!isClosed) controller.close();
      });
      socket.on("error", (err) => {
        if (!isClosed) controller.error(err);
      });
    },
    cancel() {
      isClosed = true;
      socket.destroy();
    }
  });

  const writable = new WritableStream({
    write(chunk) {
      return new Promise((resolve, reject) => {
        socket.write(Buffer.from(chunk), (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    },
    close() {
      socket.end();
    },
    abort() {
      socket.destroy();
    }
  });

  const closed = new Promise((resolve, reject) => {
    socket.on("close", (hadError) => {
      isClosed = true;
      if (hadError) reject(new Error("Socket closed with error"));
      else resolve();
    });
    socket.on("error", (err) => {
      isClosed = true;
      reject(err);
    });
  });

  return {
    readable,
    writable,
    closed,
    close: () => socket.destroy()
  };
}
