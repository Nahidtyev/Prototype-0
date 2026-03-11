const userInput = location.search;

const container = document.createElement("div");
container.innerHTML = userInput;

document.write(location.hash);

const x = document.cookie;
eval(x);

export default function App() {
  return <div>Hello</div>;
}