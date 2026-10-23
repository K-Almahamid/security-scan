export function Profile({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
