declare module "@babel/traverse" {
  import type { File, Node } from "@babel/types";

  type VisitorPath<TNode> = {
    node: TNode;
  };

  type Visitors = Record<string, (path: VisitorPath<any>) => void>;

  export default function traverse(parent: File | Node, visitors: Visitors): void;
}
