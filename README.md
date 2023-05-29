# IrinaVulnHub

总所周知，现在主流的VulnHub都只是传统的搜索CVE编号，然后再查找如何利用，或者看他人的博客，这样的方式不能说不好，但是和ChatGPT这样的庞然大物比起来那还是差太多了，可是ChatGPT又不能读取最新的信息，就算能读取，也只是使用传统搜索引擎进行搜索，针对CVE库的优化很少，所以我们考虑一个这样的使用场景，使用ChatGPT等LLMs提供一个对现有数据的读取，再由LLMs提供格式化的解释

## 原理

### LLMs上下文记忆能力

参考这个项目

[imClumsyPanda/langchain-ChatGLM: langchain-ChatGLM, local knowledge based ChatGLM with langchain ｜ 基于本地知识库的 ChatGLM 问答 (github.com)](https://github.com/imClumsyPanda/langchain-ChatGLM)

他们实现了通过向量相似度搜索完成的LLMs记忆能力

![1685167980949](image/README/1685167980949.png)

以Embedding为基础完成的相似度搜索相比起传统的全文索引或者分词分句搜索来说可能更好的理解用户的意思，并且可以给出一个 `相似度` 作为评判标准，这是传统索引做不到的

现在有了对上下文的记忆能力，下一步就可以考虑这个记忆从哪来

### 爬虫

我们考虑用爬虫从各大网站爬取公开数据，但是单纯的爬取数据肯定不行，我们需要对数据中有图片的部分进行OCR，对数据进行格式化，再把数据送给ChatGPT等比较强健的LLM进行数据整理，其中最重要的就是要对漏洞编号和涉及的组件等信息进行详细的整理，否则分词的时候可能会出问题，还有一点，我们肯定不可能就单纯的就一个CVE查找，这样太没意思了，最好是能提供一个学习的环境，比如说我问“如何进行k8s集群提权”那么应该能够给出一个详细的教学，最好是一步一步地教，因此，爬取一些博客网站就显得尤为重要，我们需要整理大量人员的博客，才能形成一个系统的教学体系

最后，因为很多CVE往往是携带附件的， 因此我们爬取的时候最好也处理一下附件，将其以类似这样的方式进行编码 `${source_url}/attachs/md5(filename)/sha1(content)/filename.ext`，最后让LLMs将${source_url}替换为最终的URL

下面是拟爬取的网站列表

| 状态 | 名称       | 域名                                                                                                                            | 备注                                   | 责任人 |
| ---- | ---------- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- | ------ |
| √   | exploit-db | [https://www.exploit-db.com/](https://www.exploit-db.com/%E8%BF%9B%E8%A1%8C%E6%90%9C%E7%B4%A2%E5%92%8C%E6%B5%8F%E8%A7%88%E3%80%82) |                                        | Yeuoly |
| ×   | metasploit | [https://www.metasploit.com/](https://www.metasploit.com/%E3%80%82)                                                                |                                        |        |
| 20%  | github     | [https://github.com/](https://github.com/)                                                                                         | 没有CVE列表，但是可以配合NVD信息一起做 | Yeuoly |
| √   | nvd        | [https://services.nvd.nist.gov/rest/json/cvehistory/2.0](https://services.nvd.nist.gov/rest/json/cvehistory/2.0)                   | 只有CVE列表                            | Yeuoly |
| ×   | 博客园     | [https://cnblogs.com](https://cnblogs.com)                                                                                         |                                        |        |
| ×   | CSDN       | [https://csdn.com](https://csdn.com)                                                                                               | 考虑先做数据清洗                       |        |
| ×   | FreeBuf    | [https://www.freebuf.com/](https://www.freebuf.com/)                                                                               |                                        |        |
| ×   | WooYun     | [https://wooyun.org/](https://wooyun.org/)                                                                                         | 数据可能比较老了                       |        |
| ×   | 零组       | [https://0-sec.org](https://0-sec.org)                                                                                             |                                        |        |
| ×   | 看雪       | [https://bbs.pediy.com](https://bbs.pediy.com)                                                                                     |                                        |        |
| ×   | 先知       | [https://xz.aliyun.com/](https://xz.aliyun.com/)                                                                                   |                                        |        |

### 爬虫思路

暂时分为两类数据，博客类和CVE类，进行不同的处理

#### 博客类

博客类需要先提取关键词，主要关键字就是各类组件/CMS，需要让LLMs进行总结这篇博客文章都写了什么，提取关键字

- 博客标题
- 博客关键信息提取
- 博客外部链接引用处理
- OCR
- 附件储存

#### CVE类

CVE类需要先在NVD等网站获取一个较为完整的CVE列表，再拿一些第三方博客网站进行CVE搜索，典型的就是github exploit-db等

- CVE列表

  - NVD
  - CNVD
- 第三方exp、poc

  - github
  - exploit-db
  - metasploit
- 语句优化

  - ChatGPT
- 格式化

  - 标题
  - 组件/CMS描述
  - 漏洞描述
  - 等级
  - PoC
  - Exp
  - 相关链接
    - 需要引用到博客上
    - 防止恶意链接

## 实现

爬虫参考本项目 [./spider](./spider) 文件夹
